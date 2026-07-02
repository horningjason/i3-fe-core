"""ASGI lifespan for i3 Functional Elements.

Startup sequence (leader worker only):
  1. Start the NTP client poller (§2.2 — process singleton).
  2. Start the SIP NOTIFY listener (§2.4 — process singleton).
  3. Initialize element and service state in the StateStore.
  4. Run the FE-supplied startup_hook (load data, warm caches, etc.).
  5. Set ElementState → Normal on success, ServiceDisruption on failure.
  6. Start the periodic NTP health monitor (§2.2 ±0.1 s budget check).

Non-leader workers skip steps 1–3 and 6; they share the StateStore and
serve read traffic normally.

Shutdown sequence:
  1. Set ElementState → GoingDown (notifies downstream subscribers).
  2. Cancel the NTP health monitor.
  3. Stop the SIP notifier.
  4. Stop the NTP client.

TODOs for future multi-worker work:
  • SO_REUSEPORT — not needed in single-worker deployment.  Add at the
    gunicorn config layer; the leader gate here means adding it later
    won't require touching this code.
  • Distributed leader election (Redis, etcd) — swap SingleWorkerContext
    for a real implementation; WorkerContext.is_leader() is already the
    only interface checked here.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from i3_fe_core.config.identity import ElementIdentity
from i3_fe_core.config.settings import CoreSettings
from i3_fe_core.discrepancy.service import DiscrepancyReporting
from i3_fe_core.logging.logging_client import LoggingClient
from i3_fe_core.notify.sip_notifier import SipNotifier
from i3_fe_core.runtime.worker import WorkerContext
from i3_fe_core.state.element_state import ElementState, ElementStateNotifier
from i3_fe_core.state.service_state import ServiceState, ServiceStateNotifier
from i3_fe_core.state.store import ElementStateBundle, InProcessStateStore, ServiceStateBundle
from i3_fe_core.time.ntp import ESINET_DRIFT_THRESHOLD_S, NtpClient

_log = logging.getLogger(__name__)


@dataclass
class LifecycleComponents:
    """All process-scoped singletons managed by the lifespan.

    Pass this to ``make_lifespan()``; store it in ``app.state`` so that
    route handlers can reach notifiers and the NTP client.
    """

    identity: ElementIdentity
    settings: CoreSettings
    worker_context: WorkerContext
    element_store: InProcessStateStore
    service_store: InProcessStateStore
    element_notifier: ElementStateNotifier
    service_notifier: ServiceStateNotifier
    ntp_client: NtpClient
    sip_notifier: SipNotifier
    logging_client: LoggingClient
    # §3.7 Discrepancy Reporting web service state (reports received/filed).
    discrepancy: DiscrepancyReporting | None = None
    # How often (seconds) to poll NTP health after startup (leader only).
    ntp_check_interval: float = 30.0
    # When True: auto-recover ElementState to Normal after ntp_recover_debounce
    # consecutive healthy NTP checks, but ONLY if the loop itself set the
    # ServiceDisruption (ownership guard — never clears an externally set state).
    ntp_auto_recover: bool = False
    # Number of consecutive healthy NTP checks required before auto-recovery.
    ntp_recover_debounce: int = 2


def make_lifespan(
    components: LifecycleComponents,
    startup_hook: Callable[[], Awaitable[None]] | None = None,
) -> Callable:
    """Return an asynccontextmanager ASGI lifespan for *components*.

    Args:
        components:    All process singletons; stored in ``app.state.i3``
                       at runtime so route handlers can read them.
        startup_hook:  Optional async callable the FE may provide to load
                       data / warm caches.  Called after singletons start.
                       Exceptions set ElementState → ServiceDisruption.
    """

    @asynccontextmanager
    async def lifespan(app) -> AsyncIterator[None]:
        is_leader = components.worker_context.is_leader()

        # --- Startup ---

        # Initialize StateStore to clean defaults.
        # For InProcessStateStore this is a no-op (defaults already set),
        # but it's explicit intent and future Redis-backed stores may need it.
        components.element_store.set_element_state(
            ElementStateBundle(state=ElementState.NORMAL, reason="")
        )
        components.service_store.set_service_state(
            ServiceStateBundle(state=ServiceState.NORMAL, reason="")
        )

        if is_leader:
            _log.info("Lifecycle: leader worker %s starting singletons",
                      components.worker_context.worker_id())
            await components.ntp_client.start()
            components.sip_notifier.start()
        else:
            _log.info("Lifecycle: non-leader worker %s — singletons skipped",
                      components.worker_context.worker_id())

        startup_ok = True
        if startup_hook is not None:
            try:
                await startup_hook()
            except Exception:
                startup_ok = False
                _log.exception(
                    "Lifecycle: startup_hook raised — setting ServiceDisruption"
                )

        if is_leader:
            if startup_ok:
                components.element_notifier.set_state(
                    ElementState.NORMAL, "Startup complete"
                )
                _log.info("Lifecycle: startup complete — ElementState=Normal")
            else:
                components.element_notifier.set_state(
                    ElementState.SERVICE_DISRUPTION, "Startup hook failed"
                )

        # NTP health monitor (leader only).
        ntp_task: asyncio.Task | None = None
        if is_leader:
            ntp_task = asyncio.create_task(
                _ntp_health_loop(components),
                name="i3-ntp-health",
            )

        # Expose components to route handlers via app state.
        app.state.i3 = components

        # --- Yield (app is running) ---
        yield

        # --- Shutdown ---
        _log.info("Lifecycle: shutting down")

        if is_leader:
            components.element_notifier.set_state(
                ElementState.GOING_DOWN, "Planned shutdown"
            )

        if ntp_task is not None:
            ntp_task.cancel()
            try:
                await ntp_task
            except asyncio.CancelledError:
                pass

        if is_leader:
            await components.sip_notifier.stop()
            await components.ntp_client.stop()

        _log.info("Lifecycle: shutdown complete")

    return lifespan


# ---------------------------------------------------------------------------
# NTP health monitor
# ---------------------------------------------------------------------------

async def _ntp_health_loop(components: LifecycleComponents) -> None:
    """Periodic §2.2 drift check; flips ElementState when NTP is unhealthy.

    Runs only on the leader worker.

    Default (ntp_auto_recover=False): sets ElementState=ServiceDisruption on
    NTP drift and never auto-clears it.  The application layer or a human
    operator owns recovery to avoid flip-flopping.

    Optional recovery (ntp_auto_recover=True): after ntp_recover_debounce
    consecutive healthy checks, sets ElementState=Normal — but ONLY when the
    loop itself previously set the ServiceDisruption (ntp_owns_disruption guard).
    A disruption set by the startup hook or other FE logic is NEVER cleared here.
    """
    ntp_owns_disruption = False
    consecutive_healthy = 0

    while True:
        await asyncio.sleep(components.ntp_check_interval)
        if not components.ntp_client.is_healthy:
            consecutive_healthy = 0
            _log.warning(
                "NTP sync degraded: drift > %.2fs or sync stale (§2.2 ESInet "
                "threshold is ±%.2fs) — setting ElementState=ServiceDisruption",
                components.ntp_client.offset or 0.0,
                ESINET_DRIFT_THRESHOLD_S,
            )
            components.element_notifier.set_state(
                ElementState.SERVICE_DISRUPTION,
                "NTP drift exceeds §2.2 ESInet threshold",
            )
            ntp_owns_disruption = True
        else:
            _log.debug("NTP health OK — offset=%.4fs", components.ntp_client.offset or 0.0)
            if components.ntp_auto_recover and ntp_owns_disruption:
                consecutive_healthy += 1
                if consecutive_healthy >= components.ntp_recover_debounce:
                    _log.info(
                        "NTP health restored after %d consecutive healthy checks — "
                        "recovering ElementState to Normal",
                        consecutive_healthy,
                    )
                    components.element_notifier.set_state(ElementState.NORMAL, "")
                    ntp_owns_disruption = False
                    consecutive_healthy = 0
