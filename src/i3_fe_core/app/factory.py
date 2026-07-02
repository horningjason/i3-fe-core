"""Application factory for i3 Functional Elements.

Usage::

    from i3_fe_core.app.factory import create_app
    from starlette.responses import JSONResponse

    def register_routes(app):
        app.add_route("/ecrf/findService", my_handler, methods=["POST"])

    app = create_app(identity=identity, settings=settings,
                     register_routes=register_routes)

The factory:
  1. Builds all process-scoped singletons (NTP, notifiers, SIP notifier,
     logging client).
  2. Wires the ASGI lifespan (startup ordering, graceful shutdown).
  3. Mounts common FE endpoints that every i3 element MUST provide:
       GET /health              — liveness probe
       GET /ElementState        — §2.4.1 element state body
       GET /ServiceState        — §2.4.2 service state body
       POST /Reports            — §3.7.1 receive a Discrepancy Report
       POST /Resolutions        — §3.7.2 resolution call-back receiver
       GET /Resolutions         — §3.7.2 resolution retrieval
       GET /StatusUpdates       — §3.7.3 DR status update
  4. Installs logging middleware that emits a LogEvent per HTTP request.
  5. Calls ``register_routes(app)`` so the FE appends its own endpoints.
  6. Returns the ready Starlette app.

Running with uvicorn (development / single-process)::

    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8443,
                ssl_certfile="server.crt", ssl_keyfile="server.key")

Running with gunicorn (production — see ENVIRONMENT CAVEAT in security/tls.py
regarding mTLS enforcement under gunicorn+UvicornWorker)::

    # gunicorn_config.py
    from i3_fe_core.security.tls import make_server_ssl_context
    from i3_fe_core.config.settings import TLSMode
    bind = "0.0.0.0:8443"
    workers = 2
    worker_class = "uvicorn.workers.UvicornWorker"
    # NOTE: pass ssl context to gunicorn, not uvicorn, in this deployment.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

import httpx
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from i3_fe_core.config.identity import ElementIdentity
from i3_fe_core.config.settings import CoreSettings, TLSMode
from i3_fe_core.discrepancy.routes import make_discrepancy_routes
from i3_fe_core.discrepancy.service import DiscrepancyReporting
from i3_fe_core.security.peer_auth import (
    PeerCertVerifier,
    ProxyClientCertMiddleware,
    load_pem_certs,
)
from i3_fe_core.security.tls import make_client_ssl_context
from i3_fe_core.logging.logevent import LogEventPrologue
from i3_fe_core.logging.logging_client import LoggingClient
from i3_fe_core.notify.sip_notifier import SipNotifier
from i3_fe_core.runtime.worker import SingleWorkerContext, WorkerContext
from i3_fe_core.state.element_state import ElementState, ElementStateNotifier
from i3_fe_core.state.service_state import ServiceState, ServiceStateNotifier
from i3_fe_core.state.store import InProcessStateStore
from i3_fe_core.time.ntp import NtpClient

from .lifecycle import LifecycleComponents, make_lifespan

_log = logging.getLogger(__name__)

_HEALTHY_STATES = frozenset({
    ElementState.NORMAL,
    ElementState.SCHEDULED_MAINTENANCE,
})


# ---------------------------------------------------------------------------
# Request logging middleware (§4.12.3.1)
# ---------------------------------------------------------------------------

class _RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Emits one LogEvent per HTTP request using the injected LoggingClient."""

    def __init__(self, app, *, logging_client: LoggingClient) -> None:
        super().__init__(app)
        self._logging_client = logging_client

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        event = LogEventPrologue(log_event_type="AccessLogEvent")
        if request.client:
            event.ip_address_port = f"{request.client.host}:{request.client.port}"
        try:
            await self._logging_client.emit(event)
        except Exception:
            _log.exception("Request logging middleware: emit failed")
        return response


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_app(
    identity: ElementIdentity,
    settings: CoreSettings,
    register_routes: Callable[[Starlette], None],
    *,
    worker_context: WorkerContext | None = None,
    ntp_client: NtpClient | None = None,
    sip_send_notify: Callable | None = None,
    logging_client: LoggingClient | None = None,
    startup_hook: Callable[[], Awaitable[None]] | None = None,
    supports_security_posture: bool = False,
    ntp_check_interval: float = 30.0,
    discrepancy: DiscrepancyReporting | None = None,
) -> Starlette:
    """Create a Starlette ASGI app wired with the i3-fe-core lifecycle.

    Args:
        identity:                 FE identity (element_id, agency_id, …).
        settings:                 Runtime config (NTP servers, TLS mode, …).
        register_routes:          Callback to add FE-specific routes to the
                                  Starlette app.  Called after common routes
                                  are installed.
        worker_context:           Leader gate.  Defaults to SingleWorkerContext.
        ntp_client:               Override for testing; built from settings by
                                  default.
        sip_send_notify:          Wire-layer callback for the SIP transport.
                                  Defaults to a debug-logging stub.
        logging_client:           Override for testing; built from settings by
                                  default.
        startup_hook:             Async callable the FE provides for custom
                                  startup (load data, cache warm-up, etc.).
                                  Failure sets ElementState → ServiceDisruption.
        supports_security_posture: Pass True to enable the securityPosture field
                                  in ServiceState NOTIFYs (§2.4.2).
        ntp_check_interval:       Seconds between NTP health checks (leader).
        discrepancy:              §3.7 Discrepancy Reporting component.  Built
                                  with defaults when omitted (every FE MUST
                                  provide the DR web service); pass your own to
                                  wire on_report / authorization hooks, a real
                                  contact jCard, or known_problem_services.
    """
    wc = worker_context or SingleWorkerContext()

    # --- Build singletons ---
    element_store = InProcessStateStore()
    service_store = InProcessStateStore()

    element_notifier = ElementStateNotifier(
        identity=identity,
        store=element_store,
    )
    service_notifier = ServiceStateNotifier(
        service=identity.element_id,
        name=identity.service_name,
        domain=identity.element_id,
        store=service_store,
        supports_security_posture=supports_security_posture,
    )

    _ntp = ntp_client or NtpClient(servers=settings.ntp_servers)

    def _default_sip_send(sub, body, mime):
        _log.debug("SIP NOTIFY stub (no wire layer configured): %s %s", mime, body)

    sip_notifier = SipNotifier(
        element_notifier=element_notifier,
        service_notifier=service_notifier,
        send_notify=sip_send_notify or _default_sip_send,
        worker_context=wc,
    )

    if logging_client is not None:
        _lc = logging_client
    else:
        # Outbound calls to the Logging Service honour the configured TLS
        # settings (§2.8.1 version floor / PFS ciphers; client cert in MTLS
        # mode) instead of httpx defaults.
        _http_client = None
        if settings.tls.mode != TLSMode.OFF:
            _http_client = httpx.AsyncClient(
                verify=make_client_ssl_context(settings.tls)
            )
        _lc = LoggingClient(
            identity=identity,
            logging_service_uri=settings.logging_service_uri,
            http_client=_http_client,
        )

    if discrepancy is None:
        # §3.7: every FE MUST provide the DR web service.  Outbound call-backs
        # and submissions honour the configured TLS settings, as for logging.
        _dr_http = None
        if settings.tls.mode != TLSMode.OFF:
            _dr_http = httpx.AsyncClient(
                verify=make_client_ssl_context(settings.tls)
            )
        discrepancy = DiscrepancyReporting(
            identity=identity,
            http_client=_dr_http,
        )

    components = LifecycleComponents(
        identity=identity,
        settings=settings,
        worker_context=wc,
        element_store=element_store,
        service_store=service_store,
        element_notifier=element_notifier,
        service_notifier=service_notifier,
        ntp_client=_ntp,
        sip_notifier=sip_notifier,
        logging_client=_lc,
        discrepancy=discrepancy,
        ntp_check_interval=ntp_check_interval,
    )

    lifespan = make_lifespan(components, startup_hook=startup_hook)

    # --- Common route handlers ---

    async def health(request: Request) -> JSONResponse:
        """Liveness probe — returns 200 OK while the element is operational."""
        bundle = element_store.get_element_state()
        ok = bundle.state in _HEALTHY_STATES
        ntp_ok = _ntp.is_healthy
        return JSONResponse(
            {
                "status": "ok" if (ok and ntp_ok) else "degraded",
                "elementState": bundle.state.value,
                "ntpHealthy": ntp_ok,
            },
            status_code=200 if (ok and ntp_ok) else 503,
        )

    async def element_state_endpoint(request: Request) -> JSONResponse:
        """§2.4.1 — current ElementState body."""
        return JSONResponse(element_notifier.get_notify_body())

    async def service_state_endpoint(request: Request) -> JSONResponse:
        """§2.4.2 — current ServiceState body."""
        return JSONResponse(service_notifier.get_notify_body())

    # --- Assemble app ---

    common_routes = [
        Route("/health", health, methods=["GET"]),
        Route("/ElementState", element_state_endpoint, methods=["GET"]),
        Route("/ServiceState", service_state_endpoint, methods=["GET"]),
        # §3.7 Discrepancy Reporting web service (Reports, Resolutions,
        # StatusUpdates) — mandatory on every FE.
        *make_discrepancy_routes(discrepancy),
    ]

    middleware = [
        Middleware(_RequestLoggingMiddleware, logging_client=_lc),
    ]

    # §5.4 compensating control: when TLS terminates at a trusted proxy,
    # mutual auth is enforced at the application layer by verifying the
    # proxy-forwarded client certificate against PCA trust anchors.
    # /ElementState and /ServiceState (and all FE routes) require a verified
    # peer; /health stays open for liveness probes.
    if settings.tls.mode == TLSMode.MTLS and settings.tls.proxy_terminated_tls:
        anchor_paths = settings.tls.pca_trust_anchors or [settings.tls.ca_path]
        anchors = [
            cert for path in anchor_paths for cert in load_pem_certs(path)
        ]
        middleware.insert(
            0,  # outermost: peer auth runs before request logging
            Middleware(
                ProxyClientCertMiddleware,
                verifier=PeerCertVerifier(anchors),
                header_name=settings.tls.client_cert_header,
                trusted_proxies=list(settings.tls.trusted_proxies),
                exempt_paths={"/health"},
            ),
        )

    app = Starlette(
        routes=common_routes,
        lifespan=lifespan,
        middleware=middleware,
    )

    # Store all components in app.state for route handlers and middleware.
    app.state.i3 = components

    # Let the FE append its own interface routes.
    register_routes(app)

    return app
