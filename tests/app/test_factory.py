"""Tests for app/factory.py — app factory, common routes, and middleware."""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.testclient import TestClient

from i3_fe_core.app.factory import create_app
from i3_fe_core.config.identity import ElementIdentity
from i3_fe_core.config.settings import CoreSettings
from i3_fe_core.state.element_state import ElementState
from i3_fe_core.state.service_state import ServiceState


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
    is_healthy: bool = True
    offset: float | None = 0.001

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass


class _FakeLoggingClient:
    def __init__(self) -> None:
        self.emitted: list[dict] = []

    async def emit(self, event) -> dict:
        body = {
            "logEventType": event.log_event_type,
            "elementId": event.element_id or "ecrf.psap.allegheny.pa.us",
        }
        self.emitted.append(body)
        return body


def _make_app(
    register_routes=None,
    *,
    fake_lc: _FakeLoggingClient | None = None,
    fake_ntp: _FakeNtpClient | None = None,
):
    """Build a test app with injected fakes; default register_routes is no-op."""
    lc = fake_lc or _FakeLoggingClient()
    ntp = fake_ntp or _FakeNtpClient()
    return create_app(
        identity=_identity(),
        settings=_settings(),
        register_routes=register_routes or (lambda app: None),
        ntp_client=ntp,
        logging_client=lc,
        ntp_check_interval=9999.0,
    ), lc


# ---------------------------------------------------------------------------
# /health endpoint
# ---------------------------------------------------------------------------

def test_health_returns_200_when_element_is_normal():
    app, _ = _make_app()
    with TestClient(app) as client:
        resp = client.get("/health")
    assert resp.status_code == 200


def test_health_body_contains_status():
    app, _ = _make_app()
    with TestClient(app) as client:
        body = client.get("/health").json()
    assert "status" in body


def test_health_body_contains_element_state():
    app, _ = _make_app()
    with TestClient(app) as client:
        body = client.get("/health").json()
    assert "elementState" in body
    assert body["elementState"] == "Normal"


def test_health_body_contains_ntp_healthy():
    app, _ = _make_app()
    with TestClient(app) as client:
        body = client.get("/health").json()
    assert "ntpHealthy" in body
    assert body["ntpHealthy"] is True


def test_health_returns_503_when_ntp_unhealthy():
    class _SickNtp(_FakeNtpClient):
        is_healthy = False

    app, _ = _make_app(fake_ntp=_SickNtp())
    with TestClient(app) as client:
        resp = client.get("/health")
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# /ElementState endpoint
# ---------------------------------------------------------------------------

def test_element_state_endpoint_returns_200():
    app, _ = _make_app()
    with TestClient(app) as client:
        resp = client.get("/ElementState")
    assert resp.status_code == 200


def test_element_state_endpoint_body_has_mandatory_fields():
    """GET /ElementState MUST return §2.4.1 body: elementId, state."""
    app, _ = _make_app()
    with TestClient(app) as client:
        body = client.get("/ElementState").json()
    assert "elementId" in body
    assert "state" in body
    assert body["state"] == "Normal"
    assert body["elementId"] == "ecrf.psap.allegheny.pa.us"


def test_element_state_endpoint_reflects_state_change():
    app, _ = _make_app()
    with TestClient(app) as client:
        # Drive a state change after startup.
        app.state.i3.element_notifier.set_state(ElementState.OVERLOADED, "test")
        body = client.get("/ElementState").json()
    assert body["state"] == "Overloaded"


# ---------------------------------------------------------------------------
# /ServiceState endpoint
# ---------------------------------------------------------------------------

def test_service_state_endpoint_returns_200():
    app, _ = _make_app()
    with TestClient(app) as client:
        resp = client.get("/ServiceState")
    assert resp.status_code == 200


def test_service_state_endpoint_body_has_mandatory_fields():
    """GET /ServiceState MUST return §2.4.2 body: service, name, domain, serviceState."""
    app, _ = _make_app()
    with TestClient(app) as client:
        body = client.get("/ServiceState").json()
    assert "service" in body
    assert "name" in body
    assert "domain" in body
    assert "serviceState" in body
    assert body["serviceState"]["state"] == "Normal"


def test_service_state_endpoint_reflects_state_change():
    app, _ = _make_app()
    with TestClient(app) as client:
        app.state.i3.service_notifier.set_state(ServiceState.OVERLOADED)
        body = client.get("/ServiceState").json()
    assert body["serviceState"]["state"] == "Overloaded"


# ---------------------------------------------------------------------------
# FE-specific routes via register_routes
# ---------------------------------------------------------------------------

def test_register_routes_callback_adds_custom_endpoint():
    def my_routes(app):
        async def dummy(request: Request) -> JSONResponse:
            return JSONResponse({"ok": True})
        app.add_route("/ecrf/test", dummy, methods=["GET"])

    app, _ = _make_app(register_routes=my_routes)
    with TestClient(app) as client:
        resp = client.get("/ecrf/test")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_register_routes_does_not_shadow_common_endpoints():
    """FE routes must not accidentally clobber /health or /ElementState."""
    app, _ = _make_app()
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/ElementState").status_code == 200
        assert client.get("/ServiceState").status_code == 200


# ---------------------------------------------------------------------------
# Logging middleware — emits LogEvent per request
# ---------------------------------------------------------------------------

def test_middleware_emits_log_event_per_request():
    """The logging middleware MUST emit a LogEvent for every HTTP request."""
    lc = _FakeLoggingClient()
    app, lc = _make_app(fake_lc=lc)
    with TestClient(app) as client:
        lc.emitted.clear()  # clear startup events
        client.get("/health")
    assert len(lc.emitted) >= 1


def test_middleware_log_event_has_access_log_type():
    lc = _FakeLoggingClient()
    app, lc = _make_app(fake_lc=lc)
    with TestClient(app) as client:
        lc.emitted.clear()
        client.get("/health")
    assert any(e["logEventType"] == "AccessLogEvent" for e in lc.emitted)


def test_middleware_emits_log_event_for_each_request():
    """One LogEvent per request — three requests → at least three events."""
    lc = _FakeLoggingClient()
    app, lc = _make_app(fake_lc=lc)
    with TestClient(app) as client:
        lc.emitted.clear()
        client.get("/health")
        client.get("/ElementState")
        client.get("/ServiceState")
    assert len(lc.emitted) >= 3


def test_middleware_does_not_fail_on_emit_error():
    """Middleware MUST NOT propagate emit exceptions to the response."""

    class _BrokenLoggingClient(_FakeLoggingClient):
        async def emit(self, event) -> dict:
            raise RuntimeError("logging broke")

    app, _ = _make_app(fake_lc=_BrokenLoggingClient())
    with TestClient(app) as client:
        resp = client.get("/health")
    # The response must still be delivered despite the middleware error.
    assert resp.status_code in (200, 503)


# ---------------------------------------------------------------------------
# app.state.i3 — components accessible to route handlers
# ---------------------------------------------------------------------------

def test_app_state_i3_set_after_startup():
    app, _ = _make_app()
    with TestClient(app):
        components = app.state.i3
    assert components is not None
    assert hasattr(components, "element_notifier")
    assert hasattr(components, "service_notifier")
    assert hasattr(components, "ntp_client")
