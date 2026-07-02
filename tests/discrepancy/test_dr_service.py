"""Tests for discrepancy/service.py — §3.7 responding and reporting roles."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from i3_fe_core.config.identity import ElementIdentity
from i3_fe_core.discrepancy.models import DiscrepancyReport
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


def _report_body(**overrides) -> dict[str, Any]:
    body = {
        "resolutionUri": "https://lis.example/dr",
        "reportType": "LoSTDiscrepancyReport",
        "discrepancyReportSubmittalTimeStamp": _TS,
        "discrepancyReportId": "dr-0001",
        "reportingAgencyName": "lis.example",
        "reportingContactJcard": _JCARD,
        "problemService": "LoST",
        "problemSeverity": "Moderate",
        "query": "findService",
        "request": "<findService/>",
        "response": "<findServiceResponse/>",
        "problem": "RouteIncorrect",
    }
    body.update(overrides)
    return body


class _FakeHttpResponse:
    def __init__(self, status_code: int = 201, body: dict | None = None) -> None:
        self.status_code = status_code
        self._body = body if body is not None else {
            "respondingAgencyName": "psap.other.example",
            "respondingContactJcard": _JCARD,
        }

    def json(self) -> dict:
        return self._body


class _FakeHttpClient:
    def __init__(self, response: _FakeHttpResponse | None = None, raise_error: bool = False):
        self.posts: list[tuple[str, dict]] = []
        self._response = response or _FakeHttpResponse()
        self._raise = raise_error

    async def post(self, url: str, json: dict | None = None) -> _FakeHttpResponse:
        if self._raise:
            raise httpx.ConnectError("connection refused")
        self.posts.append((url, json))
        return self._response


def _dr(**kwargs) -> tuple[DiscrepancyReporting, _FakeHttpClient]:
    http = kwargs.pop("http", None) or _FakeHttpClient()
    return DiscrepancyReporting(identity=_identity(), http_client=http, **kwargs), http


# ---------------------------------------------------------------------------
# Responding role — POST .../Reports (§3.7.1)
# ---------------------------------------------------------------------------

async def test_receive_valid_report_returns_201_with_mandatory_response_fields():
    dr, _ = _dr()
    status, body = await dr.receive_report(_report_body())
    assert status == 201
    assert body["respondingAgencyName"] == "psap.allegheny.pa.us"
    assert "respondingContactJcard" in body
    assert "responseEstimatedReturnTime" in body


async def test_receive_report_is_stored_with_type_specific_block():
    dr, _ = _dr()
    await dr.receive_report(_report_body())
    entry = dr.received_reports()[("lis.example", "dr-0001")]
    assert entry.report.report_specific["problem"] == "RouteIncorrect"


async def test_receive_report_missing_mandatory_returns_454():
    dr, _ = _dr()
    body = _report_body()
    del body["discrepancyReportId"]
    status, err = await dr.receive_report(body)
    assert status == 454
    assert "discrepancyReportId" in err["error"]


async def test_receive_report_unknown_type_returns_454():
    dr, _ = _dr()
    status, _err = await dr.receive_report(_report_body(reportType="BogusReport"))
    assert status == 454


async def test_receive_report_bad_severity_returns_454():
    dr, _ = _dr()
    status, _err = await dr.receive_report(_report_body(problemSeverity="Bad"))
    assert status == 454


async def test_unauthorized_reporter_returns_471_and_nothing_stored():
    dr, _ = _dr(authorize_reporter=lambda agency, request: False)
    status, _ = await dr.receive_report(_report_body())
    assert status == 471
    assert dr.received_reports() == {}


async def test_problem_service_not_ours_returns_470():
    dr, _ = _dr(known_problem_services={"ECRF"})
    status, _ = await dr.receive_report(_report_body(problemService="LoST"))
    assert status == 470


async def test_problem_service_ours_accepted():
    dr, _ = _dr(known_problem_services={"LoST"})
    status, _ = await dr.receive_report(_report_body(problemService="LoST"))
    assert status == 201


async def test_on_report_hook_invoked_with_parsed_report():
    seen: list[DiscrepancyReport] = []

    async def hook(report: DiscrepancyReport) -> None:
        seen.append(report)

    dr, _ = _dr(on_report=hook)
    await dr.receive_report(_report_body())
    assert len(seen) == 1
    assert seen[0].discrepancy_report_id == "dr-0001"


async def test_on_report_hook_failure_does_not_reject_report():
    def hook(report: DiscrepancyReport) -> None:
        raise RuntimeError("boom")

    dr, _ = _dr(on_report=hook)
    status, _ = await dr.receive_report(_report_body())
    assert status == 201
    assert ("lis.example", "dr-0001") in dr.received_reports()


# ---------------------------------------------------------------------------
# Responding role — GET .../StatusUpdates (§3.7.3)
# ---------------------------------------------------------------------------

async def test_status_update_pending_returns_200_with_estimated_return_time():
    dr, _ = _dr()
    await dr.receive_report(_report_body())
    status, body = dr.get_status_update("lis.example", "dr-0001")
    assert status == 200
    assert "responseEstimatedReturnTime" in body


def test_status_update_unknown_report_returns_473():
    dr, _ = _dr()
    status, _ = dr.get_status_update("lis.example", "nope")
    assert status == 473


async def test_status_update_after_resolution_returns_474():
    dr, _ = _dr()
    await dr.receive_report(_report_body())
    await dr.resolve("lis.example", "dr-0001", "DiscrepancyCorrected")
    status, _ = dr.get_status_update("lis.example", "dr-0001")
    assert status == 474


# ---------------------------------------------------------------------------
# Responding role — GET .../Resolutions and resolve() (§3.7.2)
# ---------------------------------------------------------------------------

async def test_get_resolution_pending_returns_475():
    dr, _ = _dr()
    await dr.receive_report(_report_body())
    status, _ = dr.get_resolution("lis.example", "dr-0001")
    assert status == 475


def test_get_resolution_unknown_report_returns_473():
    dr, _ = _dr()
    status, _ = dr.get_resolution("lis.example", "nope")
    assert status == 473


async def test_resolve_records_and_serves_resolution():
    dr, _ = _dr()
    await dr.receive_report(_report_body())
    await dr.resolve("lis.example", "dr-0001", "DiscrepancyCorrected", comments="boundary fixed")
    status, body = dr.get_resolution("lis.example", "dr-0001")
    assert status == 200
    assert body["resolution"] == "DiscrepancyCorrected"
    assert body["discrepancyReportId"] == "dr-0001"
    assert body["reportingAgencyName"] == "lis.example"
    assert body["problemService"] == "LoST"
    assert body["respondingAgencyName"] == "psap.allegheny.pa.us"
    assert "responseTime" in body


async def test_resolve_posts_callback_to_resolution_uri():
    dr, http = _dr()
    await dr.receive_report(_report_body())
    await dr.resolve("lis.example", "dr-0001", "DiscrepancyCorrected")
    # §3.7.2: POST {resolutionUri}/Resolutions
    assert len(http.posts) == 1
    url, payload = http.posts[0]
    assert url == "https://lis.example/dr/Resolutions"
    assert payload["resolution"] == "DiscrepancyCorrected"


async def test_resolve_callback_failure_still_records_resolution():
    dr, _ = _dr(http=_FakeHttpClient(raise_error=True))
    await dr.receive_report(_report_body())
    await dr.resolve("lis.example", "dr-0001", "DiscrepancyCorrected")
    status, _ = dr.get_resolution("lis.example", "dr-0001")
    assert status == 200


async def test_resolve_unknown_report_raises_key_error():
    dr, _ = _dr()
    with pytest.raises(KeyError):
        await dr.resolve("lis.example", "nope", "DiscrepancyCorrected")


# ---------------------------------------------------------------------------
# Reporting role — build_report / submit (§3.7.1 + §3.7 rate limit)
# ---------------------------------------------------------------------------

def test_build_report_fills_reporting_prolog_from_identity():
    dr, _ = _dr()
    report = dr.build_report(
        "GISDiscrepancyReport",
        "Minor",
        "https://ecrf.psap.allegheny.pa.us/dr",
        problem_service="GIS",
        report_specific={"problem": "Gap"},
    )
    assert report.reporting_agency_name == "psap.allegheny.pa.us"
    assert report.reporting_agent_id == "dispatcher1"
    assert report.reporting_contact_jcard is not None
    assert report.discrepancy_report_id  # auto-generated


async def test_submit_posts_to_reports_resource_and_stamps_timestamp():
    dr, http = _dr()
    report = dr.build_report("GISDiscrepancyReport", "Minor", "https://us.example/dr",
                             problem_service="GIS")
    result = await dr.submit(report, "https://gis.example/dr")
    assert result.status_code == 201
    assert not result.suppressed
    url, payload = http.posts[0]
    assert url == "https://gis.example/dr/Reports"
    assert "discrepancyReportSubmittalTimeStamp" in payload
    assert result.response.responding_agency_name == "psap.other.example"
    assert report.discrepancy_report_id in dr.submitted_reports()


async def test_submit_rate_limits_similar_reports():
    dr, http = _dr()
    r1 = dr.build_report("GISDiscrepancyReport", "Minor", "https://us.example/dr",
                         problem_service="GIS", report_specific={"problem": "Gap"})
    r2 = dr.build_report("GISDiscrepancyReport", "Minor", "https://us.example/dr",
                         problem_service="GIS", report_specific={"problem": "Gap"})
    first = await dr.submit(r1, "https://gis.example/dr")
    second = await dr.submit(r2, "https://gis.example/dr")
    assert first.status_code == 201
    assert second.suppressed and second.status_code is None
    assert len(http.posts) == 1


async def test_submit_dissimilar_reports_not_rate_limited():
    dr, http = _dr()
    r1 = dr.build_report("GISDiscrepancyReport", "Minor", "https://us.example/dr",
                         problem_service="GIS", report_specific={"problem": "Gap"})
    r2 = dr.build_report("GISDiscrepancyReport", "Minor", "https://us.example/dr",
                         problem_service="GIS", report_specific={"problem": "Overlap"})
    await dr.submit(r1, "https://gis.example/dr")
    result = await dr.submit(r2, "https://gis.example/dr")
    assert result.status_code == 201
    assert len(http.posts) == 2


async def test_submit_force_bypasses_rate_limit():
    dr, http = _dr()
    r1 = dr.build_report("GISDiscrepancyReport", "Minor", "https://us.example/dr",
                         problem_service="GIS", report_specific={"problem": "Gap"})
    r2 = dr.build_report("GISDiscrepancyReport", "Minor", "https://us.example/dr",
                         problem_service="GIS", report_specific={"problem": "Gap"})
    await dr.submit(r1, "https://gis.example/dr")
    result = await dr.submit(r2, "https://gis.example/dr", force=True)
    assert result.status_code == 201
    assert len(http.posts) == 2


async def test_submit_transport_failure_returns_none_status():
    dr, _ = _dr(http=_FakeHttpClient(raise_error=True))
    report = dr.build_report("GISDiscrepancyReport", "Minor", "https://us.example/dr")
    result = await dr.submit(report, "https://gis.example/dr")
    assert result.status_code is None
    assert not result.suppressed


async def test_submit_non_201_not_recorded_as_submitted():
    dr, _ = _dr(http=_FakeHttpClient(response=_FakeHttpResponse(status_code=470, body={})))
    report = dr.build_report("GISDiscrepancyReport", "Minor", "https://us.example/dr")
    result = await dr.submit(report, "https://gis.example/dr")
    assert result.status_code == 470
    assert report.discrepancy_report_id not in dr.submitted_reports()


# ---------------------------------------------------------------------------
# Reporting role — POST .../Resolutions call-back receiver (§3.7.2)
# ---------------------------------------------------------------------------

def _resolution_body(report_id: str, **overrides) -> dict[str, Any]:
    body = {
        "respondingAgencyName": "gis.example",
        "respondingContactJcard": _JCARD,
        "discrepancyReportId": report_id,
        "reportingAgencyName": "psap.allegheny.pa.us",
        "problemService": "GIS",
        "responseTime": _TS,
        "resolution": "DataCorrected",
    }
    body.update(overrides)
    return body


async def _submitted_dr() -> tuple[DiscrepancyReporting, str]:
    dr, _ = _dr()
    report = dr.build_report("GISDiscrepancyReport", "Minor", "https://us.example/dr",
                             problem_service="GIS")
    await dr.submit(report, "https://gis.example/dr")
    return dr, report.discrepancy_report_id


async def test_receive_resolution_matches_submitted_report():
    dr, report_id = await _submitted_dr()
    status, _ = dr.receive_resolution(_resolution_body(report_id))
    assert status == 201
    assert dr.submitted_reports()[report_id].resolution.resolution == "DataCorrected"


async def test_receive_resolution_unknown_report_returns_473():
    dr, _report_id = await _submitted_dr()
    status, _ = dr.receive_resolution(_resolution_body("nope"))
    assert status == 473


async def test_receive_resolution_wrong_reporting_agency_returns_473():
    dr, report_id = await _submitted_dr()
    body = _resolution_body(report_id, reportingAgencyName="someone-else.example")
    status, _ = dr.receive_resolution(body)
    assert status == 473


async def test_receive_resolution_unauthorized_responder_returns_472():
    dr, _ = _dr(authorize_responder=lambda agency, request: False)
    report = dr.build_report("GISDiscrepancyReport", "Minor", "https://us.example/dr")
    await dr.submit(report, "https://gis.example/dr")
    status, _ = dr.receive_resolution(_resolution_body(report.discrepancy_report_id))
    assert status == 472


def test_receive_resolution_missing_mandatory_returns_454():
    dr, _ = _dr()
    status, err = dr.receive_resolution({"respondingAgencyName": "gis.example"})
    assert status == 454
    assert "error" in err
