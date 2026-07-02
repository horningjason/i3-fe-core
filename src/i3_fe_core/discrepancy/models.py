"""Discrepancy Reporting wire objects — §3.7.1 (Report), §3.7.2 (Resolution),
§3.7.3 (Status Update).

Covers: NENA-STA-010.3f-2021 §3.7 (Discrepancy Reporting).

JSON key naming
---------------
Keys follow the §3.7.1–3.7.3 tables literally.  Note that §3.7.1 spells the
callback URI field ``resolutionUri`` (not ``resolutionURI``), so these models
use explicit per-field key maps instead of the generic
:func:`~i3_fe_core.logging.logevent.to_i3_json_key` converter, whose
i3-LogEvent abbreviation rules (§4.12.3.1) would uppercase the URI segment.

The §3.7.3 StatusUpdate table capitalises one field as
``RespondingContactJcard``; this is an editorial inconsistency in the
standard (every other object spells it ``respondingContactJcard``), and this
module emits the lowercase form consistently. ``StatusUpdate.from_dict()``
accepts either casing on input, in case a peer implementation followed the
standard's table literally.

reportType-dependent parameters (§3.7.1)
----------------------------------------
"The object has additional 'reportType'-dependent parameters" — e.g. a
LoSTDiscrepancyReport carries ``query``/``request``/``response``/``problem``
(§3.7.5), an MCSDiscrepancyReport carries ``ServiceCall``/``pidfLo``/``msag``/
``statusCode`` (§3.7.16).  Those travel in :attr:`DiscrepancyReport.
report_specific` and are merged into the top level of the JSON object, as the
standard requires.  The core does not validate type-specific blocks; the FE
owns its own report types.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Token registries
# ---------------------------------------------------------------------------

#: §3.7.1 problemSeverity tokens (MANDATORY field; also §10.34 Severity rows).
PROBLEM_SEVERITIES: frozenset[str] = frozenset({
    "Minor",       # e.g., format/spelling
    "Moderate",    # still functions
    "Degraded",
    "Impaired",
    "Severe",      # service down but calls can proceed
    "Critical",    # calls impaired
})

#: §3.7.1 reportType enumeration — "from the list of DRs in this section",
#: i.e. the submitted-object names defined in §3.7.4–§3.7.22.
REPORT_TYPES: frozenset[str] = frozenset({
    "PolicyStoreDiscrepancyReport",         # §3.7.4
    "LoSTDiscrepancyReport",                # §3.7.5
    "BCFDiscrepancyReport",                 # §3.7.6
    "LoggingDiscrepancyReport",             # §3.7.7
    "CallTakerDiscrepancyReport",           # §3.7.8
    "SIPDiscrepancyReport",                 # §3.7.9
    "PermissionsDiscrepancyReport",         # §3.7.10
    "GISDiscrepancyReport",                 # §3.7.11
    "LISDiscrepancyReport",                 # §3.7.12
    "PolicyDiscrepancyReport",              # §3.7.13
    "OriginatingServiceDiscrepancyReport",  # §3.7.14
    "CallTransferDiscrepancyReport",        # §3.7.15
    "MCSDiscrepancyReport",                 # §3.7.16
    "ESRPDiscrepancyReport",                # §3.7.17
    "AdrDiscrepancyReport",                 # §3.7.18
    "NetworkDiscrepancyReport",             # §3.7.19
    "IMRDiscrepancyReport",                 # §3.7.20
    "TestCallDiscrepancyReport",            # §3.7.21
    "LogSignDiscrepancyReport",             # §3.7.22
})

#: i3-specific HTTP status codes used by the DR web service (§3.7.1–3.7.3).
DR_STATUS_REASONS: dict[int, str] = {
    200: "OK",
    201: "Report Successfully Created",
    404: "Not Found",
    454: "Unspecified Error",
    470: "Unknown Service/Database (Not Ours)",
    471: "Unauthorized Reporter",
    472: "Unauthorized Responder",
    473: "Unknown ReportId",
    474: "Resolution Already Provided",
    475: "Response Not Available Yet",
}

# §2.3 i3 Timestamp: explicit UTC offset required, bare Z not allowed.
_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?[+-]\d{2}:\d{2}$"
)


def _require(d: dict[str, Any], keys: tuple[str, ...], obj_name: str) -> None:
    missing = [k for k in keys if k not in d or d[k] is None]
    if missing:
        raise ValueError(
            f"{obj_name}: missing MANDATORY field(s) {missing} (§3.7.1)"
        )


# ---------------------------------------------------------------------------
# DiscrepancyReport — §3.7.1 request body (POST .../Reports)
# ---------------------------------------------------------------------------

@dataclass
class DiscrepancyReport:
    """§3.7.1 Discrepancy Report — common prolog + reportType-specific block.

    Field conditions per the §3.7.1 table:
        resolution_uri                            MANDATORY
        report_type                               MANDATORY (REPORT_TYPES token)
        discrepancy_report_submittal_time_stamp   MANDATORY (i3 Timestamp §2.3)
        discrepancy_report_id                     MANDATORY (unique per reporting agency)
        reporting_agency_name                     MANDATORY (FQDN)
        reporting_agent_id                        OPTIONAL
        reporting_contact_jcard                   MANDATORY (jCard, RFC 7095)
        problem_service                           CONDITIONAL (required for specified DRs)
        problem_severity                          MANDATORY (PROBLEM_SEVERITIES token)
        problem_comments                          CONDITIONAL, OPTIONAL otherwise
        report_specific                           reportType-dependent parameters,
                                                  merged into the top-level JSON object

    The submittal timestamp is carried as the wire string; the reporting side
    stamps it via :func:`~i3_fe_core.time.timestamps.now_i3` at submit time.
    """

    resolution_uri: str
    report_type: str
    discrepancy_report_id: str
    reporting_agency_name: str
    reporting_contact_jcard: Any  # jCard is a JSON array (RFC 7095)
    problem_severity: str
    discrepancy_report_submittal_time_stamp: str | None = None
    reporting_agent_id: str | None = None
    problem_service: str | None = None
    problem_comments: str | None = None
    report_specific: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.report_type not in REPORT_TYPES:
            raise ValueError(
                f"reportType {self.report_type!r} is not in the §3.7 DR enumeration; "
                f"allowed: {sorted(REPORT_TYPES)}"
            )
        if self.problem_severity not in PROBLEM_SEVERITIES:
            raise ValueError(
                f"problemSeverity {self.problem_severity!r} is not a §3.7.1 token; "
                f"allowed: {sorted(PROBLEM_SEVERITIES)}"
            )
        if self.discrepancy_report_submittal_time_stamp is not None and not _TIMESTAMP_RE.match(
            self.discrepancy_report_submittal_time_stamp
        ):
            raise ValueError(
                "discrepancyReportSubmittalTimeStamp must be an i3 Timestamp with "
                f"explicit offset (§2.3), got {self.discrepancy_report_submittal_time_stamp!r}"
            )

    #: prolog snake_case field → §3.7.1 JSON key
    _KEYS = {
        "resolution_uri": "resolutionUri",
        "report_type": "reportType",
        "discrepancy_report_submittal_time_stamp": "discrepancyReportSubmittalTimeStamp",
        "discrepancy_report_id": "discrepancyReportId",
        "reporting_agency_name": "reportingAgencyName",
        "reporting_agent_id": "reportingAgentId",
        "reporting_contact_jcard": "reportingContactJcard",
        "problem_service": "problemService",
        "problem_severity": "problemSeverity",
        "problem_comments": "problemComments",
    }

    def to_dict(self) -> dict[str, Any]:
        """Serialise to the §3.7.1 JSON object.

        OPTIONAL/CONDITIONAL fields are absent (not null) when unset;
        reportType-specific parameters are merged into the top level.
        Raises ValueError if the submittal timestamp has not been stamped.
        """
        if self.discrepancy_report_submittal_time_stamp is None:
            raise ValueError(
                "discrepancyReportSubmittalTimeStamp is MANDATORY (§3.7.1) — "
                "stamp it before serialising (DiscrepancyReporting.submit() does this)"
            )
        d: dict[str, Any] = {}
        for attr, key in self._KEYS.items():
            value = getattr(self, attr)
            if value is not None:
                d[key] = value
        for key, value in self.report_specific.items():
            if key in d:
                raise ValueError(
                    f"report_specific key {key!r} collides with a §3.7.1 prolog field"
                )
            d[key] = value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> DiscrepancyReport:
        """Parse a §3.7.1 JSON object; unknown keys become ``report_specific``.

        Raises ValueError when MANDATORY prolog fields are missing or token
        fields carry values outside their registries.
        """
        _require(
            d,
            (
                "resolutionUri",
                "reportType",
                "discrepancyReportSubmittalTimeStamp",
                "discrepancyReportId",
                "reportingAgencyName",
                "reportingContactJcard",
                "problemSeverity",
            ),
            "DiscrepancyReport",
        )
        known = set(cls._KEYS.values())
        return cls(
            resolution_uri=d["resolutionUri"],
            report_type=d["reportType"],
            discrepancy_report_submittal_time_stamp=d["discrepancyReportSubmittalTimeStamp"],
            discrepancy_report_id=d["discrepancyReportId"],
            reporting_agency_name=d["reportingAgencyName"],
            reporting_agent_id=d.get("reportingAgentId"),
            reporting_contact_jcard=d["reportingContactJcard"],
            problem_service=d.get("problemService"),
            problem_severity=d["problemSeverity"],
            problem_comments=d.get("problemComments"),
            report_specific={k: v for k, v in d.items() if k not in known},
        )


# ---------------------------------------------------------------------------
# DiscrepancyReportResponse — §3.7.1 response body (201)
# ---------------------------------------------------------------------------

@dataclass
class DiscrepancyReportResponse:
    """§3.7.1 DiscrepancyReportResponse returned on successful submission."""

    responding_agency_name: str            # MANDATORY (FQDN)
    responding_contact_jcard: Any          # MANDATORY (jCard)
    responding_agent_id: str | None = None            # OPTIONAL
    response_estimated_return_time: str | None = None  # OPTIONAL (i3 Timestamp)
    response_comments: str | None = None               # OPTIONAL

    _KEYS = {
        "responding_agency_name": "respondingAgencyName",
        "responding_contact_jcard": "respondingContactJcard",
        "responding_agent_id": "respondingAgentId",
        "response_estimated_return_time": "responseEstimatedReturnTime",
        "response_comments": "responseComments",
    }

    def to_dict(self) -> dict[str, Any]:
        return {
            key: getattr(self, attr)
            for attr, key in self._KEYS.items()
            if getattr(self, attr) is not None
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> DiscrepancyReportResponse:
        _require(
            d, ("respondingAgencyName", "respondingContactJcard"), "DiscrepancyReportResponse"
        )
        return cls(
            responding_agency_name=d["respondingAgencyName"],
            responding_contact_jcard=d["respondingContactJcard"],
            responding_agent_id=d.get("respondingAgentId"),
            response_estimated_return_time=d.get("responseEstimatedReturnTime"),
            response_comments=d.get("responseComments"),
        )


# ---------------------------------------------------------------------------
# DiscrepancyResolution — §3.7.2 (POST .../Resolutions and GET .../Resolutions)
# ---------------------------------------------------------------------------

@dataclass
class DiscrepancyResolution:
    """§3.7.2 Discrepancy Resolution.

    ``resolution`` carries a DR-type-specific token (e.g. LoST:
    DiscrepancyCorrected / DiscrepancyNotFound / EntryAdded — §3.7.5;
    MCS: ProblemCorrected / NoDiscrepancy / OtherResponse — §3.7.16).
    The core does not validate it against a per-type registry; the
    responding FE owns its resolution tokens.
    """

    responding_agency_name: str          # MANDATORY
    responding_contact_jcard: Any        # MANDATORY
    discrepancy_report_id: str           # MANDATORY
    reporting_agency_name: str           # MANDATORY
    problem_service: str                 # MANDATORY
    response_time: str                   # MANDATORY (i3 Timestamp §2.3)
    resolution: str                      # MANDATORY (DR-type-specific token)
    responding_agent_id: str | None = None   # OPTIONAL
    response_comments: str | None = None      # OPTIONAL

    _KEYS = {
        "responding_agency_name": "respondingAgencyName",
        "responding_contact_jcard": "respondingContactJcard",
        "responding_agent_id": "respondingAgentId",
        "discrepancy_report_id": "discrepancyReportId",
        "reporting_agency_name": "reportingAgencyName",
        "problem_service": "problemService",
        "response_time": "responseTime",
        "response_comments": "responseComments",
        "resolution": "resolution",
    }

    def to_dict(self) -> dict[str, Any]:
        return {
            key: getattr(self, attr)
            for attr, key in self._KEYS.items()
            if getattr(self, attr) is not None
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> DiscrepancyResolution:
        _require(
            d,
            (
                "respondingAgencyName",
                "respondingContactJcard",
                "discrepancyReportId",
                "reportingAgencyName",
                "problemService",
                "responseTime",
                "resolution",
            ),
            "DiscrepancyResolution",
        )
        return cls(
            responding_agency_name=d["respondingAgencyName"],
            responding_contact_jcard=d["respondingContactJcard"],
            responding_agent_id=d.get("respondingAgentId"),
            discrepancy_report_id=d["discrepancyReportId"],
            reporting_agency_name=d["reportingAgencyName"],
            problem_service=d["problemService"],
            response_time=d["responseTime"],
            response_comments=d.get("responseComments"),
            resolution=d["resolution"],
        )


# ---------------------------------------------------------------------------
# StatusUpdate — §3.7.3 response body (GET .../StatusUpdates)
# ---------------------------------------------------------------------------

@dataclass
class StatusUpdate:
    """§3.7.3 StatusUpdate object.

    responseEstimatedReturnTime is MANDATORY: the estimated date/time when
    the resolution will be returned, or the actual time (in the past) when
    the response was provided.
    """

    responding_agency_name: str              # MANDATORY
    responding_contact_jcard: Any            # MANDATORY (see module note on casing)
    response_estimated_return_time: str      # MANDATORY (i3 Timestamp)
    responding_agent_id: str | None = None   # OPTIONAL
    status_comments: str | None = None       # OPTIONAL

    _KEYS = {
        "responding_agency_name": "respondingAgencyName",
        "responding_contact_jcard": "respondingContactJcard",
        "responding_agent_id": "respondingAgentId",
        "response_estimated_return_time": "responseEstimatedReturnTime",
        "status_comments": "statusComments",
    }

    def to_dict(self) -> dict[str, Any]:
        return {
            key: getattr(self, attr)
            for attr, key in self._KEYS.items()
            if getattr(self, attr) is not None
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> StatusUpdate:
        """Parse a §3.7.3 JSON object.

        Accepts the standard's literal ``RespondingContactJcard`` casing (see
        module note) as a fallback for ``respondingContactJcard``, since a
        peer implementation may have followed the §3.7.3 table verbatim.
        """
        jcard = d.get("respondingContactJcard", d.get("RespondingContactJcard"))
        merged = {**d, "respondingContactJcard": jcard}
        _require(
            merged,
            ("respondingAgencyName", "respondingContactJcard", "responseEstimatedReturnTime"),
            "StatusUpdate",
        )
        return cls(
            responding_agency_name=merged["respondingAgencyName"],
            responding_contact_jcard=merged["respondingContactJcard"],
            response_estimated_return_time=merged["responseEstimatedReturnTime"],
            responding_agent_id=merged.get("respondingAgentId"),
            status_comments=merged.get("statusComments"),
        )
