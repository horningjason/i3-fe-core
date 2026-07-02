"""Starlette routes for the §3.7 Discrepancy Reporting web service.

Resource names follow §3.7.1–3.7.3 exactly, mounted relative to the FE's
service URI (the Service/Agency Locator, §4.15, is what advertises this base
URI to reporters):

    POST .../Reports        — submit a DR to this element (§3.7.1)
    POST .../Resolutions    — resolution call-back for DRs this element filed (§3.7.2)
    GET  .../Resolutions    — poll the resolution of a DR filed against this element (§3.7.2)
    GET  .../StatusUpdates  — poll the status of a DR filed against this element (§3.7.3)

Error bodies: for non-2xx results the body carries the i3 reason phrase
(e.g. {"reason": "Unknown ReportId"}).  The standard defines the status
codes but no error body; a small JSON body aids debugging without
conflicting with §3.7.

Malformed requests (unparseable JSON, missing mandatory query parameters)
return 454 Unspecified Error — the standard's generic DR error code. This is
deliberate: the §3.7.1–3.7.3 tables define a closed set of status codes per
resource (e.g. POST .../Reports: 201/454/470/471) that does not include a
plain HTTP 400. Returning 454 for anything that isn't a well-formed request
keeps every response on these routes within that closed set, rather than
leaking a framework-default 400/422 that a DR client wouldn't know how to
interpret. ``_read_json`` parses the body itself (instead of letting
Starlette's ``Request.json()`` raise past this layer) specifically to keep
that guarantee — see ``test_dr_routes.py::test_post_reports_malformed_json_returns_454``.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from i3_fe_core.discrepancy.models import DR_STATUS_REASONS
from i3_fe_core.discrepancy.service import DiscrepancyReporting

_log = logging.getLogger(__name__)


def _respond(status: int, body: dict[str, Any] | None) -> JSONResponse:
    if body is None:
        body = {"reason": DR_STATUS_REASONS.get(status, "")}
    return JSONResponse(body, status_code=status)


async def _read_json(request: Request) -> dict[str, Any] | None:
    try:
        body = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return body if isinstance(body, dict) else None


def make_discrepancy_routes(dr: DiscrepancyReporting) -> list[Route]:
    """Build the four §3.7 DR routes over a DiscrepancyReporting component."""

    async def post_reports(request: Request) -> JSONResponse:
        """§3.7.1 — submit a Discrepancy Report: 201 | 454 | 470 | 471."""
        body = await _read_json(request)
        if body is None:
            return _respond(454, {"reason": "body is not a JSON object"})
        status, result = await dr.receive_report(body, request)
        return _respond(status, result)

    async def post_resolutions(request: Request) -> JSONResponse:
        """§3.7.2 — resolution call-back: 201 | 454 | 472 | 473."""
        body = await _read_json(request)
        if body is None:
            return _respond(454, {"reason": "body is not a JSON object"})
        status, result = dr.receive_resolution(body, request)
        return _respond(status, result)

    async def get_resolutions(request: Request) -> JSONResponse:
        """§3.7.2 — retrieve a resolution: 200 | 454 | 471 | 473 | 475.

        Query parameters (both MANDATORY): agencyName, discrepancyReportId.
        """
        agency = request.query_params.get("agencyName")
        report_id = request.query_params.get("discrepancyReportId")
        if not agency or not report_id:
            return _respond(
                454,
                {"reason": "agencyName and discrepancyReportId query parameters are MANDATORY"},
            )
        status, result = dr.get_resolution(agency, report_id, request)
        return _respond(status, result)

    async def get_status_updates(request: Request) -> JSONResponse:
        """§3.7.3 — status update: 200 | 454 | 471 | 473 | 474.

        Query parameters (both MANDATORY): reportingAgencyName, discrepancyReportId.
        """
        agency = request.query_params.get("reportingAgencyName")
        report_id = request.query_params.get("discrepancyReportId")
        if not agency or not report_id:
            return _respond(
                454,
                {
                    "reason": (
                        "reportingAgencyName and discrepancyReportId "
                        "query parameters are MANDATORY"
                    )
                },
            )
        status, result = dr.get_status_update(agency, report_id, request)
        return _respond(status, result)

    return [
        Route("/Reports", post_reports, methods=["POST"]),
        Route("/Resolutions", post_resolutions, methods=["POST"]),
        Route("/Resolutions", get_resolutions, methods=["GET"]),
        Route("/StatusUpdates", get_status_updates, methods=["GET"]),
    ]
