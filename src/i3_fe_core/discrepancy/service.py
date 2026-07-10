"""Discrepancy Reporting component — §3.7 responding and reporting roles.

Covers: NENA-STA-010.3f-2021 §3.7, §3.7.1 (Report), §3.7.2 (Resolution),
§3.7.3 (Status Update).

Every FE is potentially BOTH:

    Responding entity — hosts the DR web service (§3.7.1): receives
        ``POST .../Reports`` filed against it, acknowledges with a
        DiscrepancyReportResponse, answers ``GET .../StatusUpdates`` and
        ``GET .../Resolutions`` polls, and — when a human/automation resolves
        the DR — POSTs a DiscrepancyResolution to the reporter's
        ``resolutionUri`` callback (§3.7.2).

    Reporting entity — files DRs against other entities: ``submit()`` POSTs
        the report to the responder's ``.../Reports`` resource and the
        component's ``POST .../Resolutions`` route receives the resolution
        callback.

One DiscrepancyReporting instance serves both roles; ``make_discrepancy_routes``
mounts the four §3.7.1–3.7.3 resources over it.

Persistence note: reports are held in process memory (mirroring
InProcessStateStore).  "Humans will usually be responsible for generating and
acting on them" (§3.7) — production deployments whose DRs must survive a
restart should drain ``received_reports()`` to durable storage from the
``on_report`` hook and re-seed via ``restore_report()``.

Rate limiting (§3.7): "FEs creating Discrepancy Reports SHOULD limit the rate
of similar reports to avoid having the DR service become a denial of service
attack."  ``submit()`` suppresses a report when one with the same similarity
key (reportType, problemService, type-specific ``problem`` token) was sent
within ``min_similar_report_interval`` seconds; pass ``force=True`` to bypass.
"""

from __future__ import annotations

import inspect
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import httpx

from i3_fe_core.config.identity import ElementIdentity
from i3_fe_core.discrepancy.models import (
    DiscrepancyReport,
    DiscrepancyReportResponse,
    DiscrepancyResolution,
    StatusUpdate,
)
from i3_fe_core.logging.logevent import DiscrepancyReportLogEvent
from i3_fe_core.time.timestamps import format_i3, now_i3

if TYPE_CHECKING:
    from i3_fe_core.logging.logging_client import LoggingClient

_log = logging.getLogger(__name__)


def _default_jcard(identity: ElementIdentity) -> list:
    """Minimal RFC 7095 jCard identifying the operating agency.

    reportingContactJcard / respondingContactJcard are MANDATORY (§3.7.1);
    FEs SHOULD supply a real contact card with tel/email properties.
    """
    return [
        "vcard",
        [
            ["version", {}, "text", "4.0"],
            ["fn", {}, "text", identity.agency_id],
            ["kind", {}, "text", "org"],
        ],
    ]


@dataclass
class ReceivedReport:
    """A DR filed against this element (responding role)."""

    report: DiscrepancyReport
    received_at_mono: float
    estimated_return_time: str            # i3 Timestamp (§2.3)
    resolution: DiscrepancyResolution | None = None


@dataclass
class SubmittedReport:
    """A DR this element filed against another entity (reporting role)."""

    report: DiscrepancyReport
    responder_uri: str
    response: DiscrepancyReportResponse | None = None
    resolution: DiscrepancyResolution | None = None


@dataclass
class SubmitResult:
    """Outcome of :meth:`DiscrepancyReporting.submit`."""

    status_code: int | None                       # None when suppressed / transport error
    response: DiscrepancyReportResponse | None
    suppressed: bool = False                      # True when rate-limited (§3.7 SHOULD)


# Handler outcomes are (http_status, body_dict|None); routes serialise them.
_Result = tuple[int, dict[str, Any] | None]


class DiscrepancyReporting:
    """§3.7 Discrepancy Reporting — web-service state machine and client.

    Args:
        identity:            This FE's identity; supplies respondingAgencyName /
                             reportingAgencyName (agency FQDN, §2.1.1).
        contact_jcard:       jCard (RFC 7095) for the MANDATORY contact fields.
                             Defaults to a minimal org card built from identity.
        http_client:         httpx.AsyncClient used to POST reports and
                             resolution callbacks.  The app factory passes one
                             honouring the configured TLS settings (§2.8.1).
        on_report:           Optional callable (sync or async) invoked with each
                             accepted DiscrepancyReport — the FE's hook to alert
                             operators / persist the report.  Exceptions are
                             logged, never propagated to the reporter.
        authorize_reporter:  Hook(agency_fqdn, request) -> bool for the §3.7.1
                             471 Unauthorized Reporter decision on POST /Reports
                             and the GET polls.  When unset, all reporters are
                             accepted and a one-time warning is logged
                             (mirrors the SipNotifier authorization seam;
                             within an ESInet, mutual auth per §5.4 still
                             applies at the transport/middleware layer).
        authorize_responder: Hook(agency_fqdn, request) -> bool for the §3.7.2
                             472 Unauthorized Responder decision on the
                             POST /Resolutions callback.
        known_problem_services: problemService values this element answers for.
                             When a report carries a problemService not in this
                             set, POST /Reports returns 470 Unknown
                             Service/Database ("Not Ours").  Empty/None accepts
                             any (single-purpose FE deployments).
        estimated_return_window_s: Seconds from receipt used to compute the
                             MANDATORY responseEstimatedReturnTime (§3.7.3).
                             Humans act on DRs (§3.7), so this is a coarse
                             SLA default: 72 h.
        min_similar_report_interval: §3.7 SHOULD rate limit — minimum seconds
                             between submissions sharing a similarity key.
        agent_id:            Optional reportingAgentId/respondingAgentId.
                             Defaults to identity.agent_id.
        logging_client:      Optional LoggingClient. When set, a
                             DiscrepancyReportLogEvent (§4.12.3) is emitted for
                             every DR sent, received, or updated
                             (Status/Resolution). When None (default), no
                             logging occurs.
    """

    def __init__(
        self,
        identity: ElementIdentity,
        contact_jcard: list | None = None,
        *,
        http_client: httpx.AsyncClient | None = None,
        on_report: Callable[[DiscrepancyReport], Any] | None = None,
        authorize_reporter: Callable[[str, Any], bool] | None = None,
        authorize_responder: Callable[[str, Any], bool] | None = None,
        known_problem_services: set[str] | None = None,
        estimated_return_window_s: float = 72 * 3600.0,
        min_similar_report_interval: float = 600.0,
        agent_id: str | None = None,
        logging_client: "LoggingClient | None" = None,
    ) -> None:
        self._identity = identity
        self._jcard = contact_jcard if contact_jcard is not None else _default_jcard(identity)
        self._http = http_client
        self._on_report = on_report
        self._authorize_reporter = authorize_reporter
        self._authorize_responder = authorize_responder
        self._known_services = frozenset(known_problem_services or ())
        self._return_window_s = estimated_return_window_s
        self._min_similar_interval = min_similar_report_interval
        self._agent_id = agent_id if agent_id is not None else identity.agent_id
        self._logging_client = logging_client

        # Responding role: DRs filed against us, keyed per §3.7.2/§3.7.3 by
        # (reportingAgencyName, discrepancyReportId) — the id is only unique
        # per reporting agency.
        self._received: dict[tuple[str, str], ReceivedReport] = {}
        # Reporting role: DRs we filed, keyed by our discrepancyReportId.
        self._submitted: dict[str, SubmittedReport] = {}
        # §3.7 rate limiting: similarity key → monotonic time of last send.
        self._last_similar_send: dict[tuple, float] = {}

        self._warned_no_reporter_auth = False
        self._warned_no_responder_auth = False

    # ------------------------------------------------------------------
    # Responding role — §3.7.1 POST .../Reports
    # ------------------------------------------------------------------

    async def receive_report(self, body: dict[str, Any], request: Any = None) -> _Result:
        """Handle a submitted DR.  Returns (status, body) per §3.7.1:
        201 + DiscrepancyReportResponse | 454 | 470 | 471.
        """
        try:
            report = DiscrepancyReport.from_dict(body)
        except (ValueError, TypeError) as exc:
            return 454, {"error": str(exc)}

        if not self._reporter_authorized(report.reporting_agency_name, request):
            return 471, None

        if (
            report.problem_service is not None
            and self._known_services
            and report.problem_service not in self._known_services
        ):
            _log.info(
                "DR %s from %s: problemService %r is not ours (470)",
                report.discrepancy_report_id,
                report.reporting_agency_name,
                report.problem_service,
            )
            return 470, None

        key = (report.reporting_agency_name, report.discrepancy_report_id)
        estimated = format_i3(now_i3() + timedelta(seconds=self._return_window_s))
        # Resubmission with the same id replaces the stored report (the
        # standard does not define a duplicate-submission error code).
        self._received[key] = ReceivedReport(
            report=report,
            received_at_mono=time.monotonic(),
            estimated_return_time=estimated,
        )
        _log.info(
            "DR received: %s/%s type=%s severity=%s",
            report.reporting_agency_name,
            report.discrepancy_report_id,
            report.report_type,
            report.problem_severity,
        )

        if self._on_report is not None:
            try:
                result = self._on_report(report)
                if inspect.isawaitable(result):
                    await result
            except Exception:
                _log.exception("on_report hook raised; DR %s still accepted", key)

        response = DiscrepancyReportResponse(
            responding_agency_name=self._identity.agency_id,
            responding_contact_jcard=self._jcard,
            responding_agent_id=self._agent_id,
            response_estimated_return_time=estimated,
        )
        if self._logging_client is not None:
            log_event = DiscrepancyReportLogEvent(
                contents=report.to_dict(),
                type="DiscrepancyReportRequest",
                direction="incoming",
            )
            try:
                await self._logging_client.emit(log_event)
            except Exception:
                _log.exception("DiscrepancyReportLogEvent emission failed (receive_report)")
        return 201, response.to_dict()

    # ------------------------------------------------------------------
    # Responding role — §3.7.3 GET .../StatusUpdates
    # ------------------------------------------------------------------

    def get_status_update(
        self,
        reporting_agency_name: str,
        discrepancy_report_id: str,
        request: Any = None,
    ) -> _Result:
        """200 + StatusUpdate | 471 | 473 | 474 (resolution already provided)."""
        if not self._reporter_authorized(reporting_agency_name, request):
            return 471, None
        entry = self._received.get((reporting_agency_name, discrepancy_report_id))
        if entry is None:
            return 473, None
        if entry.resolution is not None:
            return 474, None
        update = StatusUpdate(
            responding_agency_name=self._identity.agency_id,
            responding_contact_jcard=self._jcard,
            responding_agent_id=self._agent_id,
            response_estimated_return_time=entry.estimated_return_time,
        )
        return 200, update.to_dict()

    # ------------------------------------------------------------------
    # Responding role — §3.7.2 GET .../Resolutions (reporter polls)
    # ------------------------------------------------------------------

    def get_resolution(
        self,
        agency_name: str,
        discrepancy_report_id: str,
        request: Any = None,
    ) -> _Result:
        """200 + DiscrepancyResolution | 471 | 473 | 475 (not available yet)."""
        if not self._reporter_authorized(agency_name, request):
            return 471, None
        entry = self._received.get((agency_name, discrepancy_report_id))
        if entry is None:
            return 473, None
        if entry.resolution is None:
            return 475, None
        return 200, entry.resolution.to_dict()

    # ------------------------------------------------------------------
    # Responding role — resolving a DR (§3.7.2 call-back)
    # ------------------------------------------------------------------

    async def resolve(
        self,
        reporting_agency_name: str,
        discrepancy_report_id: str,
        resolution: str,
        comments: str | None = None,
    ) -> DiscrepancyResolution:
        """Record the resolution of a received DR and send it to the
        reporter's resolutionUri call-back (§3.7.2: POST {resolutionUri}/Resolutions).

        ``resolution`` is the DR-type-specific token (e.g. "DataCorrected" for
        a GISDiscrepancyReport, §3.7.11).  Raises KeyError for an unknown
        report.  The resolution is recorded even if the call-back POST fails
        (the reporter can still poll GET .../Resolutions).
        """
        key = (reporting_agency_name, discrepancy_report_id)
        entry = self._received[key]
        res = DiscrepancyResolution(
            responding_agency_name=self._identity.agency_id,
            responding_contact_jcard=self._jcard,
            responding_agent_id=self._agent_id,
            discrepancy_report_id=discrepancy_report_id,
            reporting_agency_name=reporting_agency_name,
            problem_service=entry.report.problem_service
            or (self._identity.service_name or self._identity.element_id),
            response_time=format_i3(now_i3()),
            response_comments=comments,
            resolution=resolution,
        )
        entry.resolution = res

        callback = entry.report.resolution_uri.rstrip("/") + "/Resolutions"
        try:
            resp = await self._client().post(callback, json=res.to_dict())
            if resp.status_code != 201:
                _log.warning(
                    "DR %s resolution call-back to %s returned %d (expected 201); "
                    "reporter can still poll GET .../Resolutions",
                    key, callback, resp.status_code,
                )
        except httpx.HTTPError:
            _log.exception(
                "DR %s resolution call-back to %s failed; "
                "reporter can still poll GET .../Resolutions", key, callback,
            )
        if self._logging_client is not None:
            log_event = DiscrepancyReportLogEvent(
                contents=res.to_dict(),
                type="DiscrepancyResolution",
                direction="outgoing",
            )
            try:
                await self._logging_client.emit(log_event)
            except Exception:
                _log.exception("DiscrepancyReportLogEvent emission failed (resolve)")
        return res

    # ------------------------------------------------------------------
    # Reporting role — submitting DRs (§3.7.1) with §3.7 rate limiting
    # ------------------------------------------------------------------

    def build_report(
        self,
        report_type: str,
        problem_severity: str,
        resolution_uri: str,
        *,
        problem_service: str | None = None,
        problem_comments: str | None = None,
        report_specific: dict[str, Any] | None = None,
        discrepancy_report_id: str | None = None,
    ) -> DiscrepancyReport:
        """Build a DR with this element's §3.7.1 reporting prolog filled in.

        ``resolution_uri`` is the base URI of THIS element's DR web service —
        the responder POSTs its DiscrepancyResolution to
        ``{resolution_uri}/Resolutions``.
        """
        return DiscrepancyReport(
            resolution_uri=resolution_uri,
            report_type=report_type,
            discrepancy_report_id=discrepancy_report_id or str(uuid.uuid4()),
            reporting_agency_name=self._identity.agency_id,
            reporting_agent_id=self._agent_id,
            reporting_contact_jcard=self._jcard,
            problem_service=problem_service,
            problem_severity=problem_severity,
            problem_comments=problem_comments,
            report_specific=report_specific or {},
        )

    def _similarity_key(self, report: DiscrepancyReport) -> tuple:
        return (
            report.report_type,
            report.problem_service,
            report.report_specific.get("problem"),
        )

    async def submit(
        self,
        report: DiscrepancyReport,
        responder_uri: str,
        *,
        force: bool = False,
    ) -> SubmitResult:
        """Submit a DR to a responding entity (POST {responder_uri}/Reports).

        Applies the §3.7 SHOULD-level rate limit on similar reports unless
        ``force=True``.  Stamps discrepancyReportSubmittalTimeStamp at send
        time (§2.3).  Transport failures return status_code=None.
        """
        key = self._similarity_key(report)
        now_mono = time.monotonic()
        last = self._last_similar_send.get(key)
        if (
            not force
            and last is not None
            and (now_mono - last) < self._min_similar_interval
        ):
            _log.warning(
                "DR %s suppressed: similar report %s sent %.0fs ago "
                "(§3.7 rate limit, min interval %.0fs)",
                report.discrepancy_report_id, key, now_mono - last,
                self._min_similar_interval,
            )
            return SubmitResult(status_code=None, response=None, suppressed=True)

        report.discrepancy_report_submittal_time_stamp = format_i3(now_i3())
        url = responder_uri.rstrip("/") + "/Reports"
        try:
            resp = await self._client().post(url, json=report.to_dict())
        except httpx.HTTPError:
            _log.exception("DR %s submission to %s failed", report.discrepancy_report_id, url)
            if self._logging_client is not None:
                log_event = DiscrepancyReportLogEvent(
                    contents=report.to_dict(),
                    type="DiscrepancyReportRequest",
                    direction="outgoing",
                )
                try:
                    await self._logging_client.emit(log_event)
                except Exception:
                    _log.exception(
                        "DiscrepancyReportLogEvent emission failed (submit/transport-error)"
                    )
            return SubmitResult(status_code=None, response=None)

        self._last_similar_send[key] = now_mono

        parsed: DiscrepancyReportResponse | None = None
        if resp.status_code == 201:
            try:
                parsed = DiscrepancyReportResponse.from_dict(resp.json())
            except (ValueError, TypeError):
                _log.warning(
                    "DR %s: responder %s returned 201 with a non-conformant "
                    "DiscrepancyReportResponse body", report.discrepancy_report_id, url,
                )
            self._submitted[report.discrepancy_report_id] = SubmittedReport(
                report=report, responder_uri=responder_uri, response=parsed,
            )
        else:
            _log.warning(
                "DR %s submission to %s returned %d",
                report.discrepancy_report_id, url, resp.status_code,
            )
        if self._logging_client is not None:
            log_event = DiscrepancyReportLogEvent(
                contents=report.to_dict(),
                type="DiscrepancyReportRequest",
                direction="outgoing",
            )
            try:
                await self._logging_client.emit(log_event)
            except Exception:
                _log.exception("DiscrepancyReportLogEvent emission failed (submit)")
        return SubmitResult(status_code=resp.status_code, response=parsed)

    # ------------------------------------------------------------------
    # Reporting role — §3.7.2 POST .../Resolutions (call-back receiver)
    # ------------------------------------------------------------------

    def receive_resolution(self, body: dict[str, Any], request: Any = None) -> _Result:
        """Handle a DiscrepancyResolution POSTed to our resolutionUri.

        Returns (status, body) per §3.7.2: 201 | 454 | 472 | 473.
        """
        try:
            res = DiscrepancyResolution.from_dict(body)
        except (ValueError, TypeError) as exc:
            return 454, {"error": str(exc)}

        if not self._responder_authorized(res.responding_agency_name, request):
            return 472, None

        entry = self._submitted.get(res.discrepancy_report_id)
        if entry is None or res.reporting_agency_name != self._identity.agency_id:
            return 473, None

        # A responder may send an updated resolution; keep the latest.
        entry.resolution = res
        _log.info(
            "DR %s resolved by %s: %s",
            res.discrepancy_report_id, res.responding_agency_name, res.resolution,
        )
        if self._logging_client is not None:
            log_event = DiscrepancyReportLogEvent(
                contents=res.to_dict(),
                type="DiscrepancyResolution",
                direction="incoming",
            )
            try:
                self._logging_client.emit_nowait(log_event)
            except Exception:
                _log.exception("DiscrepancyReportLogEvent emission failed (receive_resolution)")
        return 201, None

    # ------------------------------------------------------------------
    # Introspection / persistence seams
    # ------------------------------------------------------------------

    def received_reports(self) -> dict[tuple[str, str], ReceivedReport]:
        """Live view of DRs filed against this element."""
        return self._received

    def submitted_reports(self) -> dict[str, SubmittedReport]:
        """Live view of DRs this element filed, keyed by discrepancyReportId."""
        return self._submitted

    def restore_report(self, entry: ReceivedReport) -> None:
        """Re-seed a previously persisted received DR (see module note)."""
        key = (entry.report.reporting_agency_name, entry.report.discrepancy_report_id)
        self._received[key] = entry

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient()
        return self._http

    def _reporter_authorized(self, agency: str, request: Any) -> bool:
        if self._authorize_reporter is None:
            if not self._warned_no_reporter_auth:
                self._warned_no_reporter_auth = True
                _log.warning(
                    "DiscrepancyReporting: no authorize_reporter hook configured — "
                    "accepting all reporters (mutual auth per §5.4 still applies "
                    "at the transport layer)"
                )
            return True
        return bool(self._authorize_reporter(agency, request))

    def _responder_authorized(self, agency: str, request: Any) -> bool:
        if self._authorize_responder is None:
            if not self._warned_no_responder_auth:
                self._warned_no_responder_auth = True
                _log.warning(
                    "DiscrepancyReporting: no authorize_responder hook configured — "
                    "accepting all resolution call-backs (mutual auth per §5.4 "
                    "still applies at the transport layer)"
                )
            return True
        return bool(self._authorize_responder(agency, request))
