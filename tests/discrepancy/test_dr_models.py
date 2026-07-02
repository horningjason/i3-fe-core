"""Tests for discrepancy/models.py — §3.7.1–3.7.3 wire objects and registries."""

from __future__ import annotations

import pytest

from i3_fe_core.discrepancy.models import (
    DR_STATUS_REASONS,
    PROBLEM_SEVERITIES,
    REPORT_TYPES,
    DiscrepancyReport,
    DiscrepancyReportResponse,
    DiscrepancyResolution,
    StatusUpdate,
)

_JCARD = ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "psap.example"]]]
_TS = "2021-06-01T12:00:00.5-04:00"


def _report(**overrides) -> DiscrepancyReport:
    kwargs = dict(
        resolution_uri="https://lis.example/dr",
        report_type="LoSTDiscrepancyReport",
        discrepancy_report_id="dr-0001",
        reporting_agency_name="lis.example",
        reporting_contact_jcard=_JCARD,
        problem_severity="Moderate",
        discrepancy_report_submittal_time_stamp=_TS,
    )
    kwargs.update(overrides)
    return DiscrepancyReport(**kwargs)


# ---------------------------------------------------------------------------
# Registries
# ---------------------------------------------------------------------------

def test_problem_severity_registry_exact():
    # §3.7.1 problemSeverity token list
    assert PROBLEM_SEVERITIES == frozenset(
        {"Minor", "Moderate", "Degraded", "Impaired", "Severe", "Critical"}
    )


def test_report_types_cover_all_standard_subsections():
    # §3.7.4–§3.7.22 define exactly 19 DR types
    assert len(REPORT_TYPES) == 19
    for expected in (
        "PolicyStoreDiscrepancyReport",
        "LoSTDiscrepancyReport",
        "MCSDiscrepancyReport",
        "GISDiscrepancyReport",
        "LogSignDiscrepancyReport",
    ):
        assert expected in REPORT_TYPES


def test_dr_status_reasons_cover_i3_codes():
    # §3.7.1–3.7.3 status code tables
    for code in (201, 454, 470, 471, 472, 473, 474, 475):
        assert code in DR_STATUS_REASONS


# ---------------------------------------------------------------------------
# DiscrepancyReport — serialisation
# ---------------------------------------------------------------------------

def test_report_to_dict_mandatory_keys_camel_case():
    d = _report().to_dict()
    for key in (
        "resolutionUri",
        "reportType",
        "discrepancyReportSubmittalTimeStamp",
        "discrepancyReportId",
        "reportingAgencyName",
        "reportingContactJcard",
        "problemSeverity",
    ):
        assert key in d


def test_report_resolution_uri_key_is_not_uppercased():
    # §3.7.1 spells it resolutionUri — the §4.12.3.1 URI-uppercasing rule
    # must NOT apply here.
    d = _report().to_dict()
    assert "resolutionUri" in d
    assert "resolutionURI" not in d


def test_report_optional_fields_absent_not_null():
    d = _report().to_dict()
    for key in ("reportingAgentId", "problemService", "problemComments"):
        assert key not in d


def test_report_optional_fields_present_when_set():
    d = _report(
        reporting_agent_id="tech1",
        problem_service="LoST",
        problem_comments="route looks wrong",
    ).to_dict()
    assert d["reportingAgentId"] == "tech1"
    assert d["problemService"] == "LoST"
    assert d["problemComments"] == "route looks wrong"


def test_report_specific_block_merged_top_level():
    # §3.7.1: reportType-dependent parameters are additional top-level members
    d = _report(
        report_specific={
            "query": "findService",
            "request": "<findService/>",
            "response": "<findServiceResponse/>",
            "problem": "RouteIncorrect",
        }
    ).to_dict()
    assert d["query"] == "findService"
    assert d["problem"] == "RouteIncorrect"


def test_report_specific_collision_with_prolog_rejected():
    with pytest.raises(ValueError, match="collides"):
        _report(report_specific={"reportType": "evil"}).to_dict()


def test_report_to_dict_requires_stamped_timestamp():
    with pytest.raises(ValueError, match="discrepancyReportSubmittalTimeStamp"):
        _report(discrepancy_report_submittal_time_stamp=None).to_dict()


# ---------------------------------------------------------------------------
# DiscrepancyReport — validation
# ---------------------------------------------------------------------------

def test_report_unknown_report_type_rejected():
    with pytest.raises(ValueError, match="reportType"):
        _report(report_type="MadeUpDiscrepancyReport")


def test_report_unknown_severity_rejected():
    with pytest.raises(ValueError, match="problemSeverity"):
        _report(problem_severity="Catastrophic")


def test_report_bare_z_timestamp_rejected():
    # §2.3: explicit offset required, bare Z not allowed
    with pytest.raises(ValueError, match="offset"):
        _report(discrepancy_report_submittal_time_stamp="2021-06-01T12:00:00Z")


# ---------------------------------------------------------------------------
# DiscrepancyReport — parsing
# ---------------------------------------------------------------------------

def test_report_round_trip():
    original = _report(
        problem_service="LoST",
        report_specific={"problem": "BelievedValid"},
    )
    parsed = DiscrepancyReport.from_dict(original.to_dict())
    assert parsed == original


def test_report_from_dict_unknown_keys_become_report_specific():
    d = _report().to_dict()
    d["statusCode"] = "468"
    parsed = DiscrepancyReport.from_dict(d)
    assert parsed.report_specific == {"statusCode": "468"}


@pytest.mark.parametrize(
    "missing",
    [
        "resolutionUri",
        "reportType",
        "discrepancyReportSubmittalTimeStamp",
        "discrepancyReportId",
        "reportingAgencyName",
        "reportingContactJcard",
        "problemSeverity",
    ],
)
def test_report_from_dict_missing_mandatory_raises(missing):
    d = _report().to_dict()
    del d[missing]
    with pytest.raises(ValueError, match=missing):
        DiscrepancyReport.from_dict(d)


# ---------------------------------------------------------------------------
# DiscrepancyReportResponse / DiscrepancyResolution / StatusUpdate
# ---------------------------------------------------------------------------

def test_response_mandatory_fields_and_optional_absent():
    d = DiscrepancyReportResponse(
        responding_agency_name="psap.example",
        responding_contact_jcard=_JCARD,
    ).to_dict()
    assert d == {
        "respondingAgencyName": "psap.example",
        "respondingContactJcard": _JCARD,
    }


def test_response_from_dict_missing_mandatory_raises():
    with pytest.raises(ValueError, match="respondingContactJcard"):
        DiscrepancyReportResponse.from_dict({"respondingAgencyName": "psap.example"})


def test_resolution_round_trip():
    res = DiscrepancyResolution(
        responding_agency_name="psap.example",
        responding_contact_jcard=_JCARD,
        discrepancy_report_id="dr-0001",
        reporting_agency_name="lis.example",
        problem_service="LoST",
        response_time=_TS,
        resolution="DiscrepancyCorrected",
    )
    assert DiscrepancyResolution.from_dict(res.to_dict()) == res


def test_resolution_to_dict_keys():
    d = DiscrepancyResolution(
        responding_agency_name="psap.example",
        responding_contact_jcard=_JCARD,
        discrepancy_report_id="dr-0001",
        reporting_agency_name="lis.example",
        problem_service="LoST",
        response_time=_TS,
        resolution="DiscrepancyCorrected",
        response_comments="fixed the boundary",
    ).to_dict()
    for key in (
        "respondingAgencyName",
        "respondingContactJcard",
        "discrepancyReportId",
        "reportingAgencyName",
        "problemService",
        "responseTime",
        "resolution",
        "responseComments",
    ):
        assert key in d


def test_status_update_mandatory_estimated_return_time():
    d = StatusUpdate(
        responding_agency_name="psap.example",
        responding_contact_jcard=_JCARD,
        response_estimated_return_time=_TS,
    ).to_dict()
    assert d["responseEstimatedReturnTime"] == _TS
    assert "statusComments" not in d


def test_status_update_round_trip():
    original = StatusUpdate(
        responding_agency_name="psap.example",
        responding_contact_jcard=_JCARD,
        response_estimated_return_time=_TS,
        responding_agent_id="tech1",
        status_comments="working on it",
    )
    assert StatusUpdate.from_dict(original.to_dict()) == original


def test_status_update_from_dict_accepts_standard_literal_casing():
    # §3.7.3's table spells this field RespondingContactJcard (unlike every
    # other DR object) — a peer that followed the table verbatim must still
    # parse.
    d = {
        "respondingAgencyName": "psap.example",
        "RespondingContactJcard": _JCARD,
        "responseEstimatedReturnTime": _TS,
    }
    parsed = StatusUpdate.from_dict(d)
    assert parsed.responding_contact_jcard == _JCARD


def test_status_update_from_dict_prefers_lowercase_when_both_present():
    d = {
        "respondingAgencyName": "psap.example",
        "respondingContactJcard": _JCARD,
        "RespondingContactJcard": ["vcard", [["fn", {}, "text", "wrong"]]],
        "responseEstimatedReturnTime": _TS,
    }
    parsed = StatusUpdate.from_dict(d)
    assert parsed.responding_contact_jcard == _JCARD


def test_status_update_from_dict_missing_mandatory_raises():
    with pytest.raises(ValueError, match="responseEstimatedReturnTime"):
        StatusUpdate.from_dict(
            {"respondingAgencyName": "psap.example", "respondingContactJcard": _JCARD}
        )
