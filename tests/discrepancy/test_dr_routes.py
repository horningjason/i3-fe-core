"""Tests for the §3.7 DR web service routes mounted by create_app()."""

from __future__ import annotations

import asyncio
from typing import Any

from starlette.testclient import TestClient

from i3_fe_core.app.factory import create_app
from i3_fe_core.config.identity import ElementIdentity
from i3_fe_core.config.settings import CoreSettings
from i3_fe_core.conformance.checks import assert_discrepancy_reporting
from i3_fe_core.discrepancy.service import DiscrepancyReporting

_JCARD = ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "lis.example"]]]
_TS = "2021-06-01T12:00:00+00:00"


def _identity() -> ElementIdentity:
    return ElementIdentity(
        element_id="ecrf.psap.allegheny.pa.us",
        agency_id="psap.allegheny.pa.us",
        agent_id="dispatcher1",
        service_id="ecrf.psap.allegheny.pa.us",
        service_name="ECRF",
    )


class _FakeNtpClient:
    is_healthy: bool = True
    offset: float | None = 0.001

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass


class _FakeLoggingClient:
    async def emit(self, event) -> dict:
        return {}


class _FakeHttpResponse:
    status_code = 201

    def json(self) -> dict:
        return {"respondingAgencyName": "x.example", "respondingContactJcard": _JCARD}


class _FakeHttpClient:
    def __init__(self) -> None:
        self.posts: list[tuple[str, dict]] = []

    async def post(self, url: str, json: dict | None = None) -> _FakeHttpResponse:
        self.posts.append((url, json))
        return _FakeHttpResponse()


def _make_app() -> tuple[Any, DiscrepancyReporting]:
    dr = DiscrepancyReporting(identity=_identity(), http_client=_FakeHttpClient())
    app = create_app(
        identity=_identity(),
        settings=CoreSettings(ntp_servers=["pool.ntp.org"]),
        register_routes=lambda app: None,
        ntp_client=_FakeNtpClient(),
        logging_client=_FakeLoggingClient(),
        ntp_check_interval=9999.0,
        discrepancy=dr,
    )
    return app, dr


def _report_body(report_id: str = "dr-0001") -> dict[str, Any]:
    return {
        "resolutionUri": "https://lis.example/dr",
        "reportType": "LoSTDiscrepancyReport",
        "discrepancyReportSubmittalTimeStamp": _TS,
        "discrepancyReportId": report_id,
        "reportingAgencyName": "lis.example",
        "reportingContactJcard": _JCARD,
        "problemService": "LoST",
        "problemSeverity": "Moderate",
        "problem": "RouteIncorrect",
    }


# ---------------------------------------------------------------------------
# Route wiring
# ---------------------------------------------------------------------------

def test_dr_routes_mounted_by_default():
    """The four §3.7 resources exist on any create_app() FE without opt-in."""
    app = create_app(
        identity=_identity(),
        settings=CoreSettings(ntp_servers=["pool.ntp.org"]),
        register_routes=lambda app: None,
        ntp_client=_FakeNtpClient(),
        logging_client=_FakeLoggingClient(),
        ntp_check_interval=9999.0,
    )
    paths = {(route.path, method) for route in app.routes for method in route.methods}
    assert ("/Reports", "POST") in paths
    assert ("/Resolutions", "POST") in paths
    assert ("/Resolutions", "GET") in paths
    assert ("/StatusUpdates", "GET") in paths


def test_post_reports_valid_returns_201():
    app, _ = _make_app()
    with TestClient(app) as client:
        resp = client.post("/Reports", json=_report_body())
    assert resp.status_code == 201
    assert "respondingAgencyName" in resp.json()


def test_post_reports_malformed_json_returns_454():
    app, _ = _make_app()
    with TestClient(app) as client:
        resp = client.post(
            "/Reports", content=b"not json", headers={"content-type": "application/json"}
        )
    assert resp.status_code == 454


def test_post_reports_non_object_json_returns_454():
    app, _ = _make_app()
    with TestClient(app) as client:
        resp = client.post("/Reports", json=["not", "an", "object"])
    assert resp.status_code == 454


def test_post_reports_empty_body_returns_454():
    # Empty body is invalid JSON (json.JSONDecodeError), not a 400/422 — the
    # §3.7.1 status-code table for this resource is a closed set (201/454/
    # 470/471) with no 400, so a body-parsing failure must stay in that set.
    app, _ = _make_app()
    with TestClient(app) as client:
        resp = client.post("/Reports", content=b"")
    assert resp.status_code == 454


def test_post_reports_invalid_utf8_body_returns_454():
    # Exercises the UnicodeDecodeError branch of _read_json — distinct code
    # path from JSONDecodeError, and the one most likely to silently regress
    # to a framework-default status code across a Starlette/httpx upgrade.
    app, _ = _make_app()
    with TestClient(app) as client:
        resp = client.post(
            "/Reports",
            content=b"\xff\xfe\x00\x01",
            headers={"content-type": "application/json"},
        )
    assert resp.status_code == 454


def test_post_resolutions_malformed_json_returns_454():
    # Same guarantee must hold on every DR route, not just /Reports.
    app, _ = _make_app()
    with TestClient(app) as client:
        resp = client.post("/Resolutions", content=b"not json")
    assert resp.status_code == 454


def test_get_status_updates_missing_params_returns_454():
    app, _ = _make_app()
    with TestClient(app) as client:
        resp = client.get("/StatusUpdates", params={"discrepancyReportId": "dr-0001"})
    assert resp.status_code == 454


def test_get_resolutions_missing_params_returns_454():
    app, _ = _make_app()
    with TestClient(app) as client:
        resp = client.get("/Resolutions", params={"agencyName": "lis.example"})
    assert resp.status_code == 454


def test_post_resolutions_unknown_report_returns_473():
    app, _ = _make_app()
    body = {
        "respondingAgencyName": "gis.example",
        "respondingContactJcard": _JCARD,
        "discrepancyReportId": "never-submitted",
        "reportingAgencyName": "psap.allegheny.pa.us",
        "problemService": "GIS",
        "responseTime": _TS,
        "resolution": "DataCorrected",
    }
    with TestClient(app) as client:
        resp = client.post("/Resolutions", json=body)
    assert resp.status_code == 473
    assert resp.json()["reason"] == "Unknown ReportId"


def test_full_report_lifecycle_over_http():
    """File → status poll → resolve → 474 status / 200 resolution."""
    app, dr = _make_app()
    params = {"reportingAgencyName": "lis.example", "discrepancyReportId": "dr-0001"}
    with TestClient(app) as client:
        assert client.post("/Reports", json=_report_body()).status_code == 201

        resp = client.get("/StatusUpdates", params=params)
        assert resp.status_code == 200
        assert "responseEstimatedReturnTime" in resp.json()

        resp = client.get(
            "/Resolutions",
            params={"agencyName": "lis.example", "discrepancyReportId": "dr-0001"},
        )
        assert resp.status_code == 475

        asyncio.run(dr.resolve("lis.example", "dr-0001", "DiscrepancyCorrected"))

        resp = client.get(
            "/Resolutions",
            params={"agencyName": "lis.example", "discrepancyReportId": "dr-0001"},
        )
        assert resp.status_code == 200
        assert resp.json()["resolution"] == "DiscrepancyCorrected"

        assert client.get("/StatusUpdates", params=params).status_code == 474


def test_conformance_helper_passes_for_default_app():
    app, _ = _make_app()
    with TestClient(app) as client:
        assert_discrepancy_reporting(client)
