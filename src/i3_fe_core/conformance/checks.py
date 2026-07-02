"""Reusable conformance assertions for NENA-STA-010.3f-2021.

FE test suites import these helpers to verify their ``create_app()`` wiring
satisfies the requirements enforced by i3-fe-core.  Each function raises
``AssertionError`` with a descriptive message on failure so standard pytest
output shows exactly which requirement was violated.

Entry points:

    ``assert_core_conformance(fe_app, identity)``
        Run the full suite against a Starlette app built with ``create_app()``.

    Granular helpers:
        ``assert_element_state_registry()``
        ``assert_service_state_registry()``
        ``assert_security_posture_registry()``
        ``assert_timestamp_has_offset(ts)``
        ``assert_element_state_notify_body(body)``
        ``assert_service_state_notify_body(body)``
        ``assert_log_event_prologue(body)``
        ``assert_ntp_reporting(ntp_client)``
        ``assert_discrepancy_reporting(client)``
"""

from __future__ import annotations

import re
import uuid

from starlette.testclient import TestClient

from i3_fe_core.state.element_state import ELEMENT_STATE_REGISTRY
from i3_fe_core.state.service_state import (
    SECURITY_POSTURE_REGISTRY,
    SERVICE_STATE_REGISTRY,
)

# ---------------------------------------------------------------------------
# Authoritative registry value sets (cross-checked against §10.12/§10.13/§10.18)
# ---------------------------------------------------------------------------

_EXPECTED_ELEMENT_STATES: frozenset[str] = frozenset({
    "Normal",
    "ScheduledMaintenance",
    "ServiceDisruption",
    "Overloaded",
    "GoingDown",
    "Down",
    "Unreachable",
})

_EXPECTED_SERVICE_STATES: frozenset[str] = frozenset({
    "Normal",
    "Unstaffed",
    "ScheduledMaintenanceDown",
    "ScheduledMaintenanceAvailable",
    "MajorIncidentInProgress",
    "Partial",
    "Overloaded",
    "GoingDown",
    "Down",
    "Unreachable",
})

_EXPECTED_SECURITY_POSTURES: frozenset[str] = frozenset({
    "Green",
    "Yellow",
    "Orange",
    "Red",
})

# §2.3 timestamp: YYYY-MM-DDThh:mm:ss[.frac]+HH:MM or -HH:MM — bare Z not allowed
_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?[+-]\d{2}:\d{2}$"
)


# ---------------------------------------------------------------------------
# Registry assertions
# ---------------------------------------------------------------------------

def assert_element_state_registry() -> None:
    """§10.13: elementState registry has exactly 7 values, matched to the standard."""
    missing = _EXPECTED_ELEMENT_STATES - ELEMENT_STATE_REGISTRY
    extra = ELEMENT_STATE_REGISTRY - _EXPECTED_ELEMENT_STATES
    assert not missing and not extra, (
        f"§10.13 elementState registry mismatch — "
        f"missing: {sorted(missing)}, extra: {sorted(extra)}"
    )
    assert len(ELEMENT_STATE_REGISTRY) == 7


def assert_service_state_registry() -> None:
    """§10.12: serviceState registry has exactly 10 values, matched to the standard."""
    missing = _EXPECTED_SERVICE_STATES - SERVICE_STATE_REGISTRY
    extra = SERVICE_STATE_REGISTRY - _EXPECTED_SERVICE_STATES
    assert not missing and not extra, (
        f"§10.12 serviceState registry mismatch — "
        f"missing: {sorted(missing)}, extra: {sorted(extra)}"
    )
    assert len(SERVICE_STATE_REGISTRY) == 10


def assert_security_posture_registry() -> None:
    """§10.18: securityPosture registry has exactly 4 values, matched to the standard."""
    missing = _EXPECTED_SECURITY_POSTURES - SECURITY_POSTURE_REGISTRY
    extra = SECURITY_POSTURE_REGISTRY - _EXPECTED_SECURITY_POSTURES
    assert not missing and not extra, (
        f"§10.18 securityPosture registry mismatch — "
        f"missing: {sorted(missing)}, extra: {sorted(extra)}"
    )
    assert len(SECURITY_POSTURE_REGISTRY) == 4


# ---------------------------------------------------------------------------
# Timestamp assertion
# ---------------------------------------------------------------------------

def assert_timestamp_has_offset(ts: str) -> None:
    """§2.3: timestamp MUST carry an explicit UTC offset (±HH:MM); bare Z not allowed."""
    assert isinstance(ts, str), f"timestamp must be a str, got {type(ts).__name__}"
    assert _TIMESTAMP_RE.match(ts), (
        f"timestamp {ts!r} is not RFC 3339 with explicit offset — "
        "bare 'Z' is not permitted; use '+00:00'"
    )


# ---------------------------------------------------------------------------
# Notify body assertions
# ---------------------------------------------------------------------------

def assert_element_state_notify_body(body: dict) -> None:
    """§2.4.1: Verify an ElementState NOTIFY body.

    - elementId MANDATORY (non-empty string)
    - state MANDATORY (must be in §10.13 registry)
    - reason OPTIONAL — when present must be a string; must never be null
    """
    assert "elementId" in body, "§2.4.1: elementId is MANDATORY in ElementState NOTIFY body"
    assert "state" in body, "§2.4.1: state is MANDATORY in ElementState NOTIFY body"

    assert isinstance(body["elementId"], str) and body["elementId"], (
        "§2.4.1: elementId must be a non-empty string"
    )
    assert body["state"] in ELEMENT_STATE_REGISTRY, (
        f"§2.4.1/§10.13: state value {body['state']!r} not in elementState registry; "
        f"allowed: {sorted(ELEMENT_STATE_REGISTRY)}"
    )

    if "reason" in body:
        assert body["reason"] is not None, (
            "§2.4.1: reason must be a string when present, not null"
        )
        assert isinstance(body["reason"], str), (
            f"§2.4.1: reason must be a string, got {type(body['reason']).__name__}"
        )


def assert_service_state_notify_body(body: dict) -> None:
    """§2.4.2: Verify a ServiceState NOTIFY body.

    - service, name, domain, serviceState MANDATORY
    - serviceState.state MANDATORY (§10.12 registry)
    - serviceState.reason MANDATORY (empty string when no reason — never null)
    - serviceId OPTIONAL; when present MUST equal domain (§2.4.2 fn.4)
    - securityPosture CONDITIONAL; when present must have posture (§10.18 registry)
    """
    for field in ("service", "name", "domain", "serviceState"):
        assert field in body, f"§2.4.2: {field!r} is MANDATORY in ServiceState NOTIFY body"

    ss = body["serviceState"]
    assert "state" in ss, "§2.4.2: serviceState.state is MANDATORY"
    assert "reason" in ss, (
        "§2.4.2: serviceState.reason is MANDATORY (empty string when no reason)"
    )
    assert ss["reason"] is not None, (
        "§2.4.2: serviceState.reason MUST be a string (empty string, not null)"
    )
    assert isinstance(ss["reason"], str), (
        f"§2.4.2: serviceState.reason must be a string, got {type(ss['reason']).__name__}"
    )
    assert ss["state"] in SERVICE_STATE_REGISTRY, (
        f"§2.4.2/§10.12: serviceState.state {ss['state']!r} not in serviceState registry; "
        f"allowed: {sorted(SERVICE_STATE_REGISTRY)}"
    )

    if "serviceId" in body:
        assert body["serviceId"] == body["domain"], (
            f"§2.4.2 fn.4: serviceId MUST equal domain when present — "
            f"serviceId={body['serviceId']!r}, domain={body['domain']!r}"
        )

    if "securityPosture" in body:
        sp = body["securityPosture"]
        assert "posture" in sp, (
            "§2.4.2: securityPosture.posture is MANDATORY when securityPosture is present"
        )
        assert sp["posture"] in SECURITY_POSTURE_REGISTRY, (
            f"§2.4.2/§10.18: securityPosture.posture {sp['posture']!r} not in registry; "
            f"allowed: {sorted(SECURITY_POSTURE_REGISTRY)}"
        )
        if "reason" in sp:
            assert sp["reason"] is not None
            assert isinstance(sp["reason"], str), (
                "§2.4.2: securityPosture.reason must be a string when present"
            )


def assert_log_event_prologue(body: dict) -> None:
    """§4.12.3.1: Verify a LogEvent prologue dict.

    - logEventType, timestamp, elementId, agencyId MANDATORY
    - timestamp must carry an explicit UTC offset (§2.3)
    - Conditional fields (agencyAgentId, callId, incidentId, callIdSIP,
      ipAddressPort) must be ABSENT (not null) when the condition is not met
    """
    for field in ("logEventType", "timestamp", "elementId", "agencyId"):
        assert field in body, f"§4.12.3.1: {field!r} is MANDATORY in LogEvent prologue"

    assert_timestamp_has_offset(body["timestamp"])

    assert isinstance(body["logEventType"], str) and body["logEventType"], (
        "§4.12.3.1: logEventType must be a non-empty string"
    )
    assert isinstance(body["elementId"], str) and body["elementId"], (
        "§4.12.3.1: elementId must be a non-empty string"
    )
    assert isinstance(body["agencyId"], str), (
        "§4.12.3.1: agencyId must be a string"
    )

    for cond in ("agencyAgentId", "callId", "incidentId", "callIdSIP", "ipAddressPort"):
        assert body.get(cond) is not None or cond not in body, (
            f"§4.12.3.1: {cond!r} must be absent (not null) when condition is not met"
        )


# ---------------------------------------------------------------------------
# NTP assertion
# ---------------------------------------------------------------------------

def assert_ntp_reporting(ntp_client: object) -> None:
    """§2.2: NTP client must be present and expose an is_healthy attribute."""
    assert ntp_client is not None, "§2.2: ntp_client must not be None"
    assert hasattr(ntp_client, "is_healthy"), (
        "§2.2: ntp_client must expose an is_healthy attribute"
    )


# ---------------------------------------------------------------------------
# Discrepancy Reporting assertion (§3.7)
# ---------------------------------------------------------------------------

def assert_discrepancy_reporting(client: TestClient) -> None:
    """§3.7: the FE MUST provide the Discrepancy Reporting web service.

    Exercises the four §3.7.1–3.7.3 resources with a probe DR:
      - POST /Reports with a valid report → 201 with the MANDATORY
        respondingAgencyName / respondingContactJcard response fields
      - GET /StatusUpdates for it → 200 with responseEstimatedReturnTime
      - GET /Resolutions before resolution → 475 Response Not Available Yet
      - GET /StatusUpdates for an unknown id → 473 Unknown ReportId
      - POST /Reports missing MANDATORY prolog fields → 454

    The probe uses a NetworkDiscrepancyReport with no problemService so it is
    accepted regardless of any known_problem_services restriction.

    Args:
        client: An open TestClient over an app built with ``create_app()``.
    """
    agency = "conformance-probe.example"
    report_id = f"conformance-{uuid.uuid4()}"
    probe = {
        "resolutionUri": "https://conformance-probe.example/dr",
        "reportType": "NetworkDiscrepancyReport",
        "discrepancyReportSubmittalTimeStamp": "2021-01-01T00:00:00+00:00",
        "discrepancyReportId": report_id,
        "reportingAgencyName": agency,
        "reportingContactJcard": ["vcard", [["version", {}, "text", "4.0"],
                                            ["fn", {}, "text", agency]]],
        "problemSeverity": "Minor",
        "problemComments": "i3-fe-core conformance probe",
    }

    resp = client.post("/Reports", json=probe)
    assert resp.status_code == 201, (
        f"§3.7.1: POST /Reports with a valid DR must return 201, got {resp.status_code}"
    )
    body = resp.json()
    for fld in ("respondingAgencyName", "respondingContactJcard"):
        assert fld in body, (
            f"§3.7.1: {fld!r} is MANDATORY in DiscrepancyReportResponse"
        )

    resp = client.get(
        "/StatusUpdates",
        params={"reportingAgencyName": agency, "discrepancyReportId": report_id},
    )
    assert resp.status_code == 200, (
        f"§3.7.3: GET /StatusUpdates for a pending DR must return 200, got {resp.status_code}"
    )
    update = resp.json()
    assert "responseEstimatedReturnTime" in update, (
        "§3.7.3: responseEstimatedReturnTime is MANDATORY in StatusUpdate"
    )
    assert_timestamp_has_offset(update["responseEstimatedReturnTime"])

    resp = client.get(
        "/Resolutions",
        params={"agencyName": agency, "discrepancyReportId": report_id},
    )
    assert resp.status_code == 475, (
        f"§3.7.2: GET /Resolutions for an unresolved DR must return "
        f"475 Response Not Available Yet, got {resp.status_code}"
    )

    resp = client.get(
        "/StatusUpdates",
        params={"reportingAgencyName": agency, "discrepancyReportId": "no-such-id"},
    )
    assert resp.status_code == 473, (
        f"§3.7.3: GET /StatusUpdates for an unknown DR must return "
        f"473 Unknown ReportId, got {resp.status_code}"
    )

    resp = client.post("/Reports", json={"reportType": "NetworkDiscrepancyReport"})
    assert resp.status_code == 454, (
        f"§3.7.1: POST /Reports missing MANDATORY prolog fields must return "
        f"454 Unspecified Error, got {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# Unified entry point
# ---------------------------------------------------------------------------

def assert_core_conformance(fe_app, identity) -> None:
    """Run the full i3-fe-core conformance suite against a Starlette ASGI app.

    Checks:
      - §10.13 elementState registry exact (7 values)
      - §10.12 serviceState registry exact (10 values)
      - §10.18 securityPosture registry exact (4 values)
      - GET /ElementState → 200 with §2.4.1-compliant body; elementId matches identity
      - GET /ServiceState → 200 with §2.4.2-compliant body
      - GET /health → 200 or 503 with status/elementState/ntpHealthy fields
      - §3.7 Discrepancy Reporting web service (Reports/Resolutions/StatusUpdates)
      - §2.2 NTP client present on app.state.i3

    Usage::

        from i3_fe_core.app.factory import create_app
        from i3_fe_core.conformance.checks import assert_core_conformance

        app = create_app(identity=my_identity, settings=settings,
                         register_routes=lambda a: None,
                         ntp_client=fake_ntp, logging_client=fake_lc)
        assert_core_conformance(app, my_identity)

    Args:
        fe_app:   A Starlette app returned by ``create_app()``.
        identity: The ``ElementIdentity`` passed to ``create_app()``; used to
                  verify that the element ID in NOTIFY bodies is correct.
    """
    # Registry checks — no running app needed
    assert_element_state_registry()
    assert_service_state_registry()
    assert_security_posture_registry()

    with TestClient(fe_app, raise_server_exceptions=True) as client:
        # --- §2.4.1 ElementState ---
        resp = client.get("/ElementState")
        assert resp.status_code == 200, (
            f"§2.4.1: GET /ElementState must return 200, got {resp.status_code}"
        )
        elem_body = resp.json()
        assert_element_state_notify_body(elem_body)
        assert elem_body["elementId"] == identity.element_id, (
            f"§2.4.1: elementId in NOTIFY body must match identity.element_id — "
            f"got {elem_body['elementId']!r}, expected {identity.element_id!r}"
        )

        # --- §2.4.2 ServiceState ---
        resp = client.get("/ServiceState")
        assert resp.status_code == 200, (
            f"§2.4.2: GET /ServiceState must return 200, got {resp.status_code}"
        )
        assert_service_state_notify_body(resp.json())

        # --- Liveness probe ---
        resp = client.get("/health")
        assert resp.status_code in (200, 503), (
            f"GET /health must return 200 or 503, got {resp.status_code}"
        )
        health = resp.json()
        for field in ("status", "elementState", "ntpHealthy"):
            assert field in health, f"GET /health body missing required field {field!r}"

        # --- §3.7 Discrepancy Reporting ---
        assert_discrepancy_reporting(client)

        # --- §2.2 NTP ---
        assert_ntp_reporting(fe_app.state.i3.ntp_client)
