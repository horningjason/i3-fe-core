"""SIP SUBSCRIBE/NOTIFY transport for emergency state event packages.

Covers: NENA-STA-010.3f-2021 §2.4 (state transport):
  • emergency-ElementState event package (§2.4.1)
  • emergency-ServiceState event package (§2.4.2)
  • RFC 6665 — SIP event notification framework (SUBSCRIBE/NOTIFY)
  • RFC 4661 — XML filter bodies in SUBSCRIBE (min-interval stored; XML
               parsing deferred to future work)
  • RFC 6446 — per-subscription minimum notification interval (rate filter +
               watchdog: the filter interval doubles as a liveness heartbeat;
               NOTIFYs are sent even when state is unchanged)

Architecture
------------
SipNotifier is the aggregation point:
  1. It registers callbacks with ElementStateNotifier and ServiceStateNotifier.
  2. SIP clients issue SUBSCRIBE requests via handle_subscribe().
  3. On each state change, the relevant notifier callback fires and SipNotifier
     fans the NOTIFY out to all active matching subscriptions.

The *send_notify* callback is the injection point for the SIP wire layer.
Production code wraps a real SIP stack; tests record calls.  This keeps the
transport decoupled from any particular SIP library.

Process singleton (§2.4.1 / §2.4.2):
  Call start() once; it consults WorkerContext.is_leader() and only activates
  subscription management on the leader worker.  Under single-worker
  deployments (the default, SingleWorkerContext) is_leader() is always True.

Forking (§2.4.1 / §2.4.2):
  Forking between elements MUST NOT be used.  Each subscription has exactly one
  Contact URI; NOTIFYs are never dispatched to multiple targets per subscription.

Subscriber authorization (§5.4):
  "Mutual Authentication MUST be used for TLS and SIP session establishment
  using a certificate traceable to the PCA."  SipNotifier itself has no view
  of the transport, so authorization is injected: pass *authorize_subscriber*
  (fed by the wire layer with the mutually-authenticated peer identity) and
  *validate_target_uri* (Contact-URI allowlist — prevents NOTIFY redirection
  to arbitrary targets).  When neither is supplied, a one-time WARNING is
  logged and the wire layer owns the whole §5.4 obligation.

ENVIRONMENT CAVEAT — gunicorn + UvicornWorker:
  When deployed behind gunicorn with UvicornWorker, TLS client-certificate
  enforcement (ssl.CERT_REQUIRED) is unreliable: gunicorn terminates TLS before
  uvicorn sees the connection, and the forwarded client cert may be unavailable.
  mTLS may silently downgrade to CERT_OPTIONAL.  The security/ layer provides
  the compensating control — security/peer_auth.py verifies the client cert
  forwarded by the trusted TLS-terminating proxy.  See §2.8 and §5.4.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from i3_fe_core.logging.logevent import SubscribeLogEvent
from i3_fe_core.runtime.worker import WorkerContext
from i3_fe_core.state.element_state import (
    EVENT_PACKAGE_NAME as ELEMENT_EVENT_PACKAGE,
    NOTIFY_MIME_TYPE as ELEMENT_MIME_TYPE,
    ElementStateNotifier,
)
from i3_fe_core.state.service_state import (
    EVENT_PACKAGE_NAME as SERVICE_EVENT_PACKAGE,
    NOTIFY_MIME_TYPE as SERVICE_MIME_TYPE,
    ServiceStateNotifier,
)

if TYPE_CHECKING:
    from i3_fe_core.logging.logging_client import LoggingClient

_log = logging.getLogger(__name__)

# Subscription duration constraints per §2.4.1 / §2.4.2.
MIN_SUBSCRIPTION_SECONDS: int = 60         # 1 minute (lower bound)
MAX_SUBSCRIPTION_SECONDS: int = 86_400     # 24 hours (upper bound — clamped silently)
DEFAULT_SUBSCRIPTION_SECONDS: int = 3_600  # 1 hour (default when Expires absent)

# Ceiling on concurrent subscriptions — bounds memory held per SUBSCRIBE
# (each unique Call-ID stores a SipSubscription plus a pending NOTIFY body).
DEFAULT_MAX_SUBSCRIPTIONS: int = 10_000

# Type alias for the injected wire-layer callback.
SendNotifyFn = Callable[["SipSubscription", dict[str, Any], str], None]


@dataclass
class SipSubscription:
    """One SUBSCRIBE registration from a remote SIP client.

    Internal coalescing/watchdog state (_pending_*, _timer_handle) is managed
    by SipNotifier and is not part of the public construction API.
    """

    subscriber_uri: str        # Contact URI — where to POST/NOTIFY
    event_package: str         # emergency-ElementState or emergency-ServiceState
    call_id: str               # SIP Call-ID (primary key in subscriptions dict)
    expires_at: float          # time.monotonic() absolute expiry
    min_notify_interval: float = 0.0  # RFC 6446 minimum interval in seconds
    subscription_id: str = ""  # §4.12.3 SubscribeLogEvent correlation id

    # Runtime state — not part of __init__ signature.
    last_notify_mono: float = field(default=0.0, compare=False)
    notify_cseq: int = field(default=0, compare=False)

    # Internal coalescing: latest body queued while timer is pending.
    _pending_body: dict[str, Any] | None = field(
        default=None, init=False, repr=False, compare=False
    )
    _pending_mime: str | None = field(
        default=None, init=False, repr=False, compare=False
    )
    # asyncio timer handle for the coalescing + watchdog timer.
    _timer_handle: asyncio.TimerHandle | None = field(
        default=None, init=False, repr=False, compare=False
    )

    @property
    def is_expired(self) -> bool:
        return time.monotonic() >= self.expires_at


@dataclass
class SipSubscribeRequest:
    """Parsed incoming SUBSCRIBE request from a SIP client."""

    event_package: str         # SIP Event header value
    subscriber_uri: str        # Contact URI of the subscriber
    call_id: str               # SIP Call-ID header
    expires: int | None = None # Expires header; None → use server default
    min_notify_interval: float = 0.0  # From RFC 6446 / RFC 4661 filter body
    # Raw RFC 4661 XML filter body, if present — stored for future extension.
    filter_body: str | None = None


@dataclass
class SipResponse:
    """Simplified SIP response descriptor (subset relevant to tests and callers).

    Wire note: when status_code == 423 the wire layer MUST emit a
    ``Min-Expires: <min_expires>`` SIP header (RFC 3261 §21.4.16 /
    RFC 6665 §4.1.2.1).  The min_expires field carries the value.
    """

    status_code: int       # 200 OK / 423 Interval Too Brief / 489 Bad Event / 503 Unavailable
    reason: str
    expires: int | None = None      # Negotiated Expires echoed in 200 OK
    min_expires: int | None = None  # 423 only: MUST become Min-Expires on the wire


class SipNotifier:
    """SIP transport for emergency-ElementState and emergency-ServiceState.

    See module docstring for architecture, constraints, and the gunicorn mTLS caveat.
    """

    def __init__(
        self,
        element_notifier: ElementStateNotifier,
        service_notifier: ServiceStateNotifier,
        send_notify: SendNotifyFn,
        worker_context: WorkerContext | None = None,
        max_subscriptions: int = DEFAULT_MAX_SUBSCRIPTIONS,
        authorize_subscriber: Callable[[SipSubscribeRequest], bool] | None = None,
        validate_target_uri: Callable[[str], bool] | None = None,
        logging_client: "LoggingClient | None" = None,
    ) -> None:
        """
        Args:
            element_notifier:     ElementState publisher to fan out from.
            service_notifier:     ServiceState publisher to fan out from.
            send_notify:          Wire-layer NOTIFY callback.
            worker_context:       Leader gate; None = always leader.
            max_subscriptions:    Concurrent-subscription ceiling.
            authorize_subscriber: §5.4 authorization hook — the wire layer feeds
                                  the mutually-authenticated peer identity into
                                  this decision.  Return False to reject the
                                  SUBSCRIBE with 403 Forbidden.
            validate_target_uri:  Contact-URI allowlist hook.  Return False to
                                  reject with 403 before any subscription is
                                  stored or NOTIFY dispatched (prevents NOTIFY
                                  redirection/amplification to arbitrary targets).
            logging_client:       Optional LoggingClient. When set, a
                                  SubscribeLogEvent (§4.12.3) is emitted for every
                                  processed SUBSCRIBE (accepted or rejected). When
                                  None (default), no logging occurs.

        When NEITHER hook is provided, SUBSCRIBEs are accepted as before, but a
        one-time WARNING is logged: §5.4 mutual authentication must then be
        fully enforced by the SIP wire layer.
        """
        self._element_notifier = element_notifier
        self._service_notifier = service_notifier
        self._send_notify = send_notify
        self._worker_context = worker_context
        self._max_subscriptions = max_subscriptions
        self._authorize_subscriber = authorize_subscriber
        self._validate_target_uri = validate_target_uri
        self._logging_client = logging_client
        self._unguarded_subscribe_warned = False
        self._subscriptions: dict[str, SipSubscription] = {}
        self._cleanup_task: asyncio.Task[None] | None = None
        self._active = False

        # Register as downstream of both state publishers.
        element_notifier.subscribe(self._on_element_state)
        service_notifier.subscribe(self._on_service_state)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Activate subscription management (leader-only gate).

        Returns True when this worker is the leader and the notifier is active.
        Returns False when another worker holds leadership (no SIP port bound
        here; subscriptions are handled by the leader process).
        """
        if self._worker_context is not None and not self._worker_context.is_leader():
            _log.info("SipNotifier: not leader — subscription listener not started")
            return False

        self._active = True
        try:
            loop = asyncio.get_running_loop()
            self._cleanup_task = loop.create_task(
                self._subscription_cleanup_loop(),
                name="sip-sub-cleanup",
            )
        except RuntimeError:
            pass

        _log.info("SipNotifier started on leader worker")
        return True

    async def stop(self) -> None:
        """Deactivate and cancel background tasks."""
        if self._cleanup_task is not None:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
        # Cancel all pending subscription timers.
        for sub in self._subscriptions.values():
            if sub._timer_handle is not None:
                sub._timer_handle.cancel()
        self._active = False

    # ------------------------------------------------------------------
    # SUBSCRIBE processing (§2.4.1 / §2.4.2)
    # ------------------------------------------------------------------

    def handle_subscribe(self, request: SipSubscribeRequest) -> SipResponse:
        """Process an incoming SIP SUBSCRIBE request.

        Status codes:
          200 OK                 — subscription accepted (or unsubscribe acknowledged)
          403 Forbidden          — subscriber not authorized, or Contact URI rejected
          423 Interval Too Brief — Expires below the minimum; Min-Expires carries the floor
          489 Bad Event          — event package not recognised
          503 Service Unavailable — subscription capacity reached (new Call-IDs only;
                                    refreshes of existing subscriptions still succeed)
        """
        existing_sub = self._subscriptions.get(request.call_id)
        existing_before = existing_sub is not None
        purpose = "refresh" if existing_before else "initial"
        subscription_id = (
            existing_sub.subscription_id
            if existing_sub is not None
            else f"urn:emergency:uid:subid:{uuid.uuid4()}"
        )

        # Validate event package.
        valid = {ELEMENT_EVENT_PACKAGE, SERVICE_EVENT_PACKAGE}
        if request.event_package not in valid:
            self._log_subscribe(request, 489, purpose, subscription_id)
            return SipResponse(
                status_code=489,
                reason=f"Bad Event: {request.event_package!r} is not a recognised package",
            )

        # §5.4 subscriber authorization + Contact-URI validation.  Both run
        # before ANY state change — an unauthorized peer must not be able to
        # subscribe, refresh, or unsubscribe, and an unvetted Contact URI must
        # never be stored or receive a NOTIFY.
        if self._authorize_subscriber is None and self._validate_target_uri is None:
            if not self._unguarded_subscribe_warned:
                self._unguarded_subscribe_warned = True
                _log.warning(
                    "SipNotifier: no authorize_subscriber or validate_target_uri "
                    "hook configured — SUBSCRIBEs are accepted without "
                    "application-layer authorization.  §5.4 mutual "
                    "authentication MUST be enforced by the SIP wire layer in "
                    "this configuration."
                )
        else:
            if self._authorize_subscriber is not None and not self._authorize_subscriber(
                request
            ):
                _log.warning(
                    "SUBSCRIBE rejected (403): subscriber %r not authorized "
                    "(call_id=%r)",
                    request.subscriber_uri,
                    request.call_id,
                )
                self._log_subscribe(request, 403, purpose, subscription_id)
                return SipResponse(status_code=403, reason="Forbidden")
            if self._validate_target_uri is not None and not self._validate_target_uri(
                request.subscriber_uri
            ):
                _log.warning(
                    "SUBSCRIBE rejected (403): Contact URI %r failed target "
                    "validation (call_id=%r)",
                    request.subscriber_uri,
                    request.call_id,
                )
                self._log_subscribe(request, 403, purpose, subscription_id)
                return SipResponse(status_code=403, reason="Forbidden")

        # Expires == 0 → explicit unsubscribe.
        if request.expires == 0:
            removed = self._subscriptions.pop(request.call_id, None)
            if removed and removed._timer_handle:
                removed._timer_handle.cancel()
            self._log_subscribe(request, 200, "terminate", subscription_id)
            return SipResponse(status_code=200, reason="OK", expires=0)

        # Negotiate duration.
        requested = (
            request.expires
            if request.expires is not None
            else DEFAULT_SUBSCRIPTION_SECONDS
        )
        if requested < MIN_SUBSCRIPTION_SECONDS:
            self._log_subscribe(request, 423, purpose, subscription_id)
            return SipResponse(
                status_code=423,
                reason="Interval Too Brief",
                min_expires=MIN_SUBSCRIPTION_SECONDS,
            )
        negotiated = min(requested, MAX_SUBSCRIPTION_SECONDS)

        # Capacity gate — bounds memory against SUBSCRIBE floods with unique
        # Call-IDs.  Refreshes of existing subscriptions are always accepted.
        if (
            request.call_id not in self._subscriptions
            and len(self._subscriptions) >= self._max_subscriptions
        ):
            _log.warning(
                "SUBSCRIBE rejected: subscription capacity (%d) reached",
                self._max_subscriptions,
            )
            self._log_subscribe(request, 503, purpose, subscription_id)
            return SipResponse(
                status_code=503,
                reason="Service Unavailable: subscription capacity reached",
            )

        sub = SipSubscription(
            subscriber_uri=request.subscriber_uri,
            event_package=request.event_package,
            call_id=request.call_id,
            expires_at=time.monotonic() + negotiated,
            min_notify_interval=request.min_notify_interval,
            subscription_id=subscription_id,
        )
        # Cancel old timer if refreshing an existing subscription.
        old = self._subscriptions.get(request.call_id)
        if old and old._timer_handle:
            old._timer_handle.cancel()
        self._subscriptions[request.call_id] = sub

        # §2.4.1 / §2.4.2: send an initial NOTIFY with the current state.
        self._send_current_state_notify(sub)

        self._log_subscribe(request, 200, purpose, subscription_id)
        return SipResponse(status_code=200, reason="OK", expires=negotiated)

    # ------------------------------------------------------------------
    # State-change callbacks from the notifier layer
    # ------------------------------------------------------------------

    def _on_element_state(self, body: dict[str, Any]) -> None:
        self._fan_out(ELEMENT_EVENT_PACKAGE, body, ELEMENT_MIME_TYPE)

    def _on_service_state(self, body: dict[str, Any]) -> None:
        self._fan_out(SERVICE_EVENT_PACKAGE, body, SERVICE_MIME_TYPE)

    def _log_subscribe(
        self,
        request: "SipSubscribeRequest",
        status_code: int,
        purpose: str,
        subscription_id: str,
    ) -> None:
        """Emit a SubscribeLogEvent (§4.12.3) if a logging_client is set."""
        if self._logging_client is None:
            return
        event = SubscribeLogEvent(
            package=request.event_package,
            peer=request.subscriber_uri,
            parameter=None,
            expiration=(
                str(request.expires) if request.expires is not None else None
            ),
            response=status_code,
            purpose=purpose,
            direction="incoming",
            subscription_id=subscription_id,
        )
        try:
            self._logging_client.emit_nowait(event)
        except Exception:
            _log.exception("SubscribeLogEvent emission failed")

    # ------------------------------------------------------------------
    # Fan-out
    # ------------------------------------------------------------------

    def _fan_out(
        self, event_package: str, body: dict[str, Any], mime_type: str
    ) -> None:
        """Deliver a NOTIFY to each active, matching subscription."""
        expired: list[str] = []
        for call_id, sub in self._subscriptions.items():
            if sub.is_expired:
                expired.append(call_id)
                continue
            if sub.event_package != event_package:
                continue
            self._rate_filtered_deliver(sub, body, mime_type)
        for call_id in expired:
            _log.debug("Removing expired subscription %s", call_id)
            self._subscriptions.pop(call_id, None)

    def _rate_filtered_deliver(
        self, sub: SipSubscription, body: dict[str, Any], mime_type: str
    ) -> None:
        """Honour the RFC 6446 per-subscription minimum notification interval.

        If enough time has passed since the last NOTIFY, send immediately.
        Otherwise queue the body (latest wins) and let the running timer pick
        it up — the timer also serves as a watchdog heartbeat (§2.4.1/§2.4.2).
        """
        elapsed = time.monotonic() - sub.last_notify_mono
        if sub.min_notify_interval == 0 or elapsed >= sub.min_notify_interval:
            self._deliver_notify(sub, body, mime_type)
            return

        # Within the rate window — update pending; the timer already handles delivery.
        sub._pending_body = body
        sub._pending_mime = mime_type
        # If no timer is running, schedule one.  (The timer is also scheduled
        # after every _deliver_notify when min_interval > 0, so normally one
        # is already in flight here.)
        if sub._timer_handle is None:
            self._schedule_notify_timer(sub)

    def _deliver_notify(
        self, sub: SipSubscription, body: dict[str, Any], mime_type: str
    ) -> None:
        """Deliver the NOTIFY and reset coalescing state.

        After delivery, if the subscription has a rate filter, schedule the
        next watchdog/coalescing timer so that even if state does not change,
        a NOTIFY will still be sent at the minimum interval (watchdog, §2.4.1).
        """
        if sub._timer_handle is not None:
            sub._timer_handle.cancel()
            sub._timer_handle = None
        sub._pending_body = None
        sub._pending_mime = None
        sub.last_notify_mono = time.monotonic()
        sub.notify_cseq += 1
        try:
            self._send_notify(sub, body, mime_type)
        except Exception:
            _log.exception("NOTIFY delivery failed for %s", sub.subscriber_uri)

        # Schedule watchdog for next cycle (only when rate filter is active).
        if sub.min_notify_interval > 0:
            self._schedule_notify_timer(sub)

    def _schedule_notify_timer(self, sub: SipSubscription) -> None:
        """Schedule (or re-schedule) the coalescing + watchdog timer."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if sub._timer_handle is not None:
            return
        sub._timer_handle = loop.call_later(
            sub.min_notify_interval,
            self._timer_fired,
            sub,
        )

    def _timer_fired(self, sub: SipSubscription) -> None:
        """Called when the per-subscription coalescing/watchdog timer fires."""
        sub._timer_handle = None
        if sub.is_expired:
            return

        if sub._pending_body is not None:
            # A coalesced state change is waiting.
            body, mime = sub._pending_body, sub._pending_mime
        else:
            # No pending change — send current state as watchdog heartbeat.
            if sub.event_package == ELEMENT_EVENT_PACKAGE:
                body = self._element_notifier.get_notify_body()
                mime = ELEMENT_MIME_TYPE
            else:
                body = self._service_notifier.get_notify_body()
                mime = SERVICE_MIME_TYPE

        self._deliver_notify(sub, body, mime)  # type: ignore[arg-type]

    def _send_current_state_notify(self, sub: SipSubscription) -> None:
        """Send the current state as the initial NOTIFY for a new subscription."""
        if sub.event_package == ELEMENT_EVENT_PACKAGE:
            body = self._element_notifier.get_notify_body()
            mime = ELEMENT_MIME_TYPE
        else:
            body = self._service_notifier.get_notify_body()
            mime = SERVICE_MIME_TYPE
        self._deliver_notify(sub, body, mime)

    # ------------------------------------------------------------------
    # Background maintenance
    # ------------------------------------------------------------------

    async def _subscription_cleanup_loop(self) -> None:
        """Periodically prune expired subscriptions (defensive; fan-out also prunes)."""
        while True:
            await asyncio.sleep(60)
            expired = [
                cid for cid, sub in self._subscriptions.items() if sub.is_expired
            ]
            for cid in expired:
                sub = self._subscriptions.pop(cid)
                if sub._timer_handle:
                    sub._timer_handle.cancel()
            if expired:
                _log.debug("Pruned %d expired subscriptions", len(expired))
