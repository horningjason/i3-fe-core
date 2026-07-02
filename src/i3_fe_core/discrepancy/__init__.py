"""Discrepancy Reporting (§3.7) — generic DR web service and client.

Every functional element described in NENA-STA-010.3f-2021 MUST support the
discrepancy report function (§3.7): "Each database, service, and agency MUST
provide a Discrepancy Reporting web service."

This package provides:
    models   — §3.7.1–3.7.3 wire objects and token registries
    service  — DiscrepancyReporting component (responding + reporting roles)
    routes   — Starlette routes for the four DR endpoints
"""

from i3_fe_core.discrepancy.models import (
    DR_STATUS_REASONS,
    PROBLEM_SEVERITIES,
    REPORT_TYPES,
    DiscrepancyReport,
    DiscrepancyReportResponse,
    DiscrepancyResolution,
    StatusUpdate,
)
from i3_fe_core.discrepancy.routes import make_discrepancy_routes
from i3_fe_core.discrepancy.service import DiscrepancyReporting, SubmitResult

__all__ = [
    "DR_STATUS_REASONS",
    "PROBLEM_SEVERITIES",
    "REPORT_TYPES",
    "DiscrepancyReport",
    "DiscrepancyReportResponse",
    "DiscrepancyResolution",
    "StatusUpdate",
    "DiscrepancyReporting",
    "SubmitResult",
    "make_discrepancy_routes",
]
