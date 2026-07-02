"""Tests for app/lifecycle.py — startup/shutdown state machine."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock

import pytest
from starlette.testclient import TestClient

from i3_fe_core.app.factory import create_app
from i3_fe_core.app.lifecycle import LifecycleComponents, _ntp_health_loop
from i3_fe_core.config.identity import ElementIdentity
from i3_fe_core.config.settings import CoreSettings
from i3_fe_core.logging.logging_client import LoggingClient
from i3_fe_core.notify.sip_notifier import SipNotifier
from i3_fe_core.runtime.worker import SingleWorkerContext, WorkerContext
from i3_fe_core.state.element_state import ElementState, ElementStateNotifier
from i3_fe_core.state.service_state import ServiceState, ServiceStateNotifier
from i3_fe_core.state.store import InProcessStateStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _identity() -> ElementIdentity:
    return ElementIdentity(
        element_id="ecrf.psap.allegheny.pa.us",
        agency_id="psap.allegheny.pa.us",
        agent_id="dispatcher1",
        service_id="ecrf.psap.allegheny.pa.us",
        service_name="ECRF",
    )


def _settings() -> CoreSettings:
    return CoreSettings(ntp_servers=["pool.ntp.org"])


class _FakeNtpClient:
    """NTP client stub: no network, configurable health flag."""
    is_healthy: bool = True
    offset: float | None = 0.001

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass


class _FakeLoggingClient:
    """Records emit() calls without touching the network."""
    emitted: list[Any]

    def __init__(self) -> None:
        self.emitted = []

    async def emit(self, event) -> dict:
        body = {"logEventType": event.log_event_type}
        self.emitted.append(body)
        return body


def _make_app(
    *,
    startup_hook: Callable[[], Awaitable[None]] | None = None,
    worker_context: WorkerContext | None = None,
    ntp_client: _FakeNtpClient | None = None,
    fake_lc: _FakeLoggingClient | None = None,
) -> Any:
    identity = _identity()
    settings = _settings()
    lc = fake_lc or _FakeLoggingClient()
    ntp = ntp_client or _FakeNtpClient()

    return create_app(
        identity=identity,
        settings=settings,
        register_routes=lambda app: None,
        worker_context=worker_context or SingleWorkerContext(),
        ntp_client=ntp,
        logging_client=lc,
        startup_hook=startup_hook,
        ntp_check_interval=9999.0,  # disable in-test NTP health checks
    )


# ---------------------------------------------------------------------------
# Startup — state transitions
# ---------------------------------------------------------------------------

def test_startup_sets_element_state_normal():
    """Successful startup MUST set ElementState → Normal."""
    app = _make_app()
    with TestClient(app):
        resp = app.state.i3.element_store.get_element_state()
        assert resp.state == ElementState.NORMAL


def test_startup_hook_failure_sets_service_disruption():
    """Startup hook exception MUST set ElementState → ServiceDisruption."""

    async def failing_hook():
        raise RuntimeError("intentional failure")

    app = _make_app(startup_hook=failing_hook)
    with TestClient(app):
        resp = app.state.i3.element_store.get_element_state()
        assert resp.state == ElementState.SERVICE_DISRUPTION


def test_successful_startup_hook_does_not_set_degraded():
    """Successful startup hook must leave ElementState as Normal."""

    calls: list[str] = []

    async def good_hook():
        calls.append("ran")

    app = _make_app(startup_hook=good_hook)
    with TestClient(app):
        assert calls == ["ran"]
        assert app.state.i3.element_store.get_element_state().state == ElementState.NORMAL


# ---------------------------------------------------------------------------
# Shutdown — state transitions
# ---------------------------------------------------------------------------

def test_shutdown_sets_going_down():
    """On shutdown, the leader MUST set ElementState → GoingDown."""
    app = _make_app()
    states: list[ElementState] = []

    with TestClient(app):
        e_notifier: ElementStateNotifier = app.state.i3.element_notifier
        e_notifier.subscribe(lambda body: states.append(body["state"]))

    # After context-manager exit, GoingDown should have been set.
    assert "GoingDown" in states


# ---------------------------------------------------------------------------
# Leader gate — non-leader skips singletons
# ---------------------------------------------------------------------------

def test_non_leader_does_not_call_ntp_start():
    """Non-leader workers MUST NOT start the NTP client."""

    class _FollowerWorker(WorkerContext):
        def is_leader(self) -> bool:
            return False
        def worker_id(self) -> str:
            return "follower-0"

    started: list[bool] = []

    class _SpyNtpClient(_FakeNtpClient):
        async def start(self) -> None:
            started.append(True)

    app = _make_app(
        worker_context=_FollowerWorker(),
        ntp_client=_SpyNtpClient(),
    )
    with TestClient(app):
        pass

    assert started == [], "Non-leader must not start NTP client"


def test_non_leader_does_not_set_element_state_normal():
    """Non-leader workers must NOT set ElementState — the leader owns it."""
    class _FollowerWorker(WorkerContext):
        def is_leader(self) -> bool:
            return False
        def worker_id(self) -> str:
            return "follower-0"

    app = _make_app(worker_context=_FollowerWorker())
    with TestClient(app):
        # Non-leader initialises the store to Normal via set_element_state()
        # for the store reset, but does NOT transition via the notifier.
        notified: list[str] = []
        app.state.i3.element_notifier.subscribe(lambda b: notified.append(b["state"]))

    # No state-change notifications from a follower (we subscribed AFTER startup).
    assert notified == []


# ---------------------------------------------------------------------------
# NTP health monitor
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ntp_health_loop_sets_service_disruption_when_unhealthy():
    """_ntp_health_loop MUST flip ElementState when NTP goes unhealthy."""
    identity = _identity()
    settings = _settings()
    element_store = InProcessStateStore()
    service_store = InProcessStateStore()
    e_notifier = ElementStateNotifier(identity=identity, store=element_store)
    s_notifier = ServiceStateNotifier(
        service=identity.element_id,
        name=identity.service_name,
        domain=identity.element_id,
        store=service_store,
    )

    class _UnhealthyNtp(_FakeNtpClient):
        is_healthy = False
        offset = 0.5  # way over §2.2 threshold

    ntp = _UnhealthyNtp()
    lc = _FakeLoggingClient()

    sip = SipNotifier(e_notifier, s_notifier, lambda s, b, m: None)

    components = LifecycleComponents(
        identity=identity,
        settings=settings,
        worker_context=SingleWorkerContext(),
        element_store=element_store,
        service_store=service_store,
        element_notifier=e_notifier,
        service_notifier=s_notifier,
        ntp_client=ntp,
        sip_notifier=sip,
        logging_client=lc,
        ntp_check_interval=0.05,  # very short for test
    )

    states: list[str] = []
    e_notifier.subscribe(lambda b: states.append(b["state"]))

    task = asyncio.create_task(_ntp_health_loop(components))
    await asyncio.sleep(0.12)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert "ServiceDisruption" in states


@pytest.mark.asyncio
async def test_ntp_health_loop_does_not_change_state_when_healthy():
    """_ntp_health_loop MUST NOT change state when NTP is healthy."""
    identity = _identity()
    settings = _settings()
    element_store = InProcessStateStore()
    service_store = InProcessStateStore()
    e_notifier = ElementStateNotifier(identity=identity, store=element_store)
    s_notifier = ServiceStateNotifier(
        service=identity.element_id,
        name=identity.service_name,
        domain=identity.element_id,
        store=service_store,
    )
    ntp = _FakeNtpClient()  # is_healthy = True
    lc = _FakeLoggingClient()
    sip = SipNotifier(e_notifier, s_notifier, lambda s, b, m: None)

    components = LifecycleComponents(
        identity=identity,
        settings=settings,
        worker_context=SingleWorkerContext(),
        element_store=element_store,
        service_store=service_store,
        element_notifier=e_notifier,
        service_notifier=s_notifier,
        ntp_client=ntp,
        sip_notifier=sip,
        logging_client=lc,
        ntp_check_interval=0.05,
    )

    states: list[str] = []
    e_notifier.subscribe(lambda b: states.append(b["state"]))

    task = asyncio.create_task(_ntp_health_loop(components))
    await asyncio.sleep(0.12)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert "ServiceDisruption" not in states


@pytest.mark.asyncio
async def test_ntp_no_auto_recover_by_default():
    """Default (ntp_auto_recover=False): ServiceDisruption set by NTP is never auto-cleared."""
    identity = _identity()
    settings = _settings()
    element_store = InProcessStateStore()
    service_store = InProcessStateStore()
    e_notifier = ElementStateNotifier(identity=identity, store=element_store)
    s_notifier = ServiceStateNotifier(
        service=identity.element_id,
        name=identity.service_name,
        domain=identity.element_id,
        store=service_store,
    )
    lc = _FakeLoggingClient()
    sip = SipNotifier(e_notifier, s_notifier, lambda s, b, m: None)
    ntp = _FakeNtpClient()
    ntp.is_healthy = False

    components = LifecycleComponents(
        identity=identity,
        settings=settings,
        worker_context=SingleWorkerContext(),
        element_store=element_store,
        service_store=service_store,
        element_notifier=e_notifier,
        service_notifier=s_notifier,
        ntp_client=ntp,
        sip_notifier=sip,
        logging_client=lc,
        ntp_check_interval=0.05,
        # ntp_auto_recover defaults to False
    )

    states: list[str] = []
    e_notifier.subscribe(lambda b: states.append(b["state"]))

    task = asyncio.create_task(_ntp_health_loop(components))
    await asyncio.sleep(0.08)
    assert "ServiceDisruption" in states

    ntp.is_healthy = True
    states.clear()

    # Several healthy checks should fire; with auto_recover=False, no recovery.
    await asyncio.sleep(0.15)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert "Normal" not in states


@pytest.mark.asyncio
async def test_ntp_auto_recover_clears_disruption_after_debounce():
    """With ntp_auto_recover=True, ElementState returns to Normal after debounce healthy checks."""
    identity = _identity()
    settings = _settings()
    element_store = InProcessStateStore()
    service_store = InProcessStateStore()
    e_notifier = ElementStateNotifier(identity=identity, store=element_store)
    s_notifier = ServiceStateNotifier(
        service=identity.element_id,
        name=identity.service_name,
        domain=identity.element_id,
        store=service_store,
    )
    lc = _FakeLoggingClient()
    sip = SipNotifier(e_notifier, s_notifier, lambda s, b, m: None)
    ntp = _FakeNtpClient()
    ntp.is_healthy = False

    components = LifecycleComponents(
        identity=identity,
        settings=settings,
        worker_context=SingleWorkerContext(),
        element_store=element_store,
        service_store=service_store,
        element_notifier=e_notifier,
        service_notifier=s_notifier,
        ntp_client=ntp,
        sip_notifier=sip,
        logging_client=lc,
        ntp_check_interval=0.05,
        ntp_auto_recover=True,
        ntp_recover_debounce=2,
    )

    states: list[str] = []
    e_notifier.subscribe(lambda b: states.append(b["state"]))

    task = asyncio.create_task(_ntp_health_loop(components))
    # One unhealthy check fires → ServiceDisruption.
    await asyncio.sleep(0.08)
    assert "ServiceDisruption" in states

    ntp.is_healthy = True
    states.clear()

    # After debounce=2 checks (2 × 0.05 s = 0.10 s) + margin → auto-recover.
    await asyncio.sleep(0.15)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert "Normal" in states


@pytest.mark.asyncio
async def test_ntp_loop_does_not_clear_externally_set_disruption():
    """The NTP loop MUST NOT clear a ServiceDisruption it did not set (ownership guard)."""
    identity = _identity()
    settings = _settings()
    element_store = InProcessStateStore()
    service_store = InProcessStateStore()
    e_notifier = ElementStateNotifier(identity=identity, store=element_store)
    s_notifier = ServiceStateNotifier(
        service=identity.element_id,
        name=identity.service_name,
        domain=identity.element_id,
        store=service_store,
    )
    lc = _FakeLoggingClient()
    sip = SipNotifier(e_notifier, s_notifier, lambda s, b, m: None)
    ntp = _FakeNtpClient()  # always healthy — NTP loop never sets disruption

    components = LifecycleComponents(
        identity=identity,
        settings=settings,
        worker_context=SingleWorkerContext(),
        element_store=element_store,
        service_store=service_store,
        element_notifier=e_notifier,
        service_notifier=s_notifier,
        ntp_client=ntp,
        sip_notifier=sip,
        logging_client=lc,
        ntp_check_interval=0.05,
        ntp_auto_recover=True,
        ntp_recover_debounce=2,
    )

    # External code sets ServiceDisruption before the loop starts.
    e_notifier.set_state(ElementState.SERVICE_DISRUPTION, "external cause")

    states: list[str] = []
    e_notifier.subscribe(lambda b: states.append(b["state"]))

    task = asyncio.create_task(_ntp_health_loop(components))
    # Multiple healthy checks — more than the debounce window.
    await asyncio.sleep(0.20)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    # The loop must not have emitted a Normal transition.
    assert "Normal" not in states
