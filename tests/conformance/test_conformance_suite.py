"""Conformance suite tests.

Builds a minimal Functional Element using ``create_app()`` and runs
``assert_core_conformance()`` plus the granular helpers against it.

If these tests pass, the conformance helpers are themselves correct, and any FE
that passes them satisfies the cross-cutting requirements of NENA-STA-010.3f-2021
that i3-fe-core enforces.
"""

from __future__ import annotations

import pytest

from i3_fe_core.app.factory import create_app
from i3_fe_core.config.identity import ElementIdentity
from i3_fe_core.config.settings import CoreSettings
from i3_fe_core.conformance.checks import (
    assert_core_conformance,
    assert_element_state_notify_body,
    assert_element_state_registry,
    assert_log_event_prologue,
    assert_ntp_reporting,
    assert_security_posture_registry,
    assert_service_state_notify_body,
    assert_service_state_registry,
    assert_timestamp_has_offset,
)


# ---------------------------------------------------------------------------
# Shared test-FE helpers (mirrors the pattern from Prompt 6 test FE)
# ---------------------------------------------------------------------------

def _identity() -> ElementIdentity:
    return ElementIdentity(
        element_id="lvf.psap.allegheny.pa.us",
        agency_id="psap.allegheny.pa.us",
        agent_id="dispatcher1",
        service_id="lvf.psap.allegheny.pa.us",
        service_name="LVF",
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
            "elementId": event.element_id or "lvf.psap.allegheny.pa.us",
        }
        self.emitted.append(body)
        return body


def _make_fe_app(*, supports_security_posture: bool = False):
    return create_app(
        identity=_identity(),
        settings=_settings(),
        register_routes=lambda app: None,
        ntp_client=_FakeNtpClient(),
        logging_client=_FakeLoggingClient(),
        ntp_check_interval=9999.0,
        supports_security_posture=supports_security_posture,
    )


# ---------------------------------------------------------------------------
# Registry assertions
# ---------------------------------------------------------------------------

def test_element_state_registry_exact_seven_values():
    """§10.13: elementState registry must have exactly 7 values."""
    assert_element_state_registry()


def test_service_state_registry_exact_ten_values():
    """§10.12: serviceState registry must have exactly 10 values."""
    assert_service_state_registry()


def test_security_posture_registry_exact_four_values():
    """§10.18: securityPosture registry must have exactly 4 values."""
    assert_security_posture_registry()


# ---------------------------------------------------------------------------
# Timestamp assertions (§2.3)
# ---------------------------------------------------------------------------

def test_timestamp_with_positive_offset_passes():
    assert_timestamp_has_offset("2025-08-21T12:58:03.01+05:00")


def test_timestamp_with_negative_offset_passes():
    assert_timestamp_has_offset("2025-08-21T12:58:03-05:00")


def test_timestamp_utc_plus_zero_passes():
    assert_timestamp_has_offset("2025-08-21T12:58:03.010+00:00")


def test_timestamp_bare_z_fails():
    """§2.3: bare Z MUST NOT be used; explicit ±HH:MM is required."""
    with pytest.raises(AssertionError, match="explicit offset"):
        assert_timestamp_has_offset("2025-08-21T12:58:03Z")


def test_timestamp_no_offset_fails():
    with pytest.raises(AssertionError):
        assert_timestamp_has_offset("2025-08-21T12:58:03")


# ---------------------------------------------------------------------------
# ElementState NOTIFY body assertions (§2.4.1)
# ---------------------------------------------------------------------------

def test_element_state_body_normal_passes():
    assert_element_state_notify_body({
        "elementId": "lvf.psap.allegheny.pa.us",
        "state": "Normal",
    })


def test_element_state_body_with_reason_passes():
    assert_element_state_notify_body({
        "elementId": "lvf.psap.allegheny.pa.us",
        "state": "Overloaded",
        "reason": "Too many concurrent queries",
    })


def test_element_state_body_missing_element_id_fails():
    with pytest.raises(AssertionError, match="elementId"):
        assert_element_state_notify_body({"state": "Normal"})


def test_element_state_body_missing_state_fails():
    with pytest.raises(AssertionError, match="state"):
        assert_element_state_notify_body({"elementId": "lvf.psap.allegheny.pa.us"})


def test_element_state_body_invalid_state_value_fails():
    """State value not in §10.13 registry must fail."""
    with pytest.raises(AssertionError, match="registry"):
        assert_element_state_notify_body({
            "elementId": "lvf.psap.allegheny.pa.us",
            "state": "Bogus",
        })


def test_element_state_body_null_reason_fails():
    """reason must be absent, not null, when not applicable."""
    with pytest.raises(AssertionError):
        assert_element_state_notify_body({
            "elementId": "lvf.psap.allegheny.pa.us",
            "state": "Normal",
            "reason": None,
        })


# ---------------------------------------------------------------------------
# ServiceState NOTIFY body assertions (§2.4.2)
# ---------------------------------------------------------------------------

def test_service_state_body_minimal_passes():
    assert_service_state_notify_body({
        "service": "lvf.psap.allegheny.pa.us",
        "name": "LVF",
        "domain": "lvf.psap.allegheny.pa.us",
        "serviceState": {"state": "Normal", "reason": ""},
    })


def test_service_state_body_with_security_posture_passes():
    assert_service_state_notify_body({
        "service": "lvf.psap.allegheny.pa.us",
        "name": "LVF",
        "domain": "lvf.psap.allegheny.pa.us",
        "serviceState": {"state": "Normal", "reason": ""},
        "securityPosture": {"posture": "Green"},
    })


def test_service_state_body_service_id_equal_domain_passes():
    assert_service_state_notify_body({
        "service": "lvf.psap.allegheny.pa.us",
        "name": "LVF",
        "domain": "lvf.psap.allegheny.pa.us",
        "serviceId": "lvf.psap.allegheny.pa.us",
        "serviceState": {"state": "Normal", "reason": ""},
    })


def test_service_state_body_service_id_not_equal_domain_fails():
    """§2.4.2 fn.4: serviceId MUST equal domain when present."""
    with pytest.raises(AssertionError, match="serviceId MUST equal domain"):
        assert_service_state_notify_body({
            "service": "lvf.psap.allegheny.pa.us",
            "name": "LVF",
            "domain": "lvf.psap.allegheny.pa.us",
            "serviceId": "other.psap.allegheny.pa.us",
            "serviceState": {"state": "Normal", "reason": ""},
        })


def test_service_state_body_invalid_state_fails():
    with pytest.raises(AssertionError, match="registry"):
        assert_service_state_notify_body({
            "service": "lvf.psap.allegheny.pa.us",
            "name": "LVF",
            "domain": "lvf.psap.allegheny.pa.us",
            "serviceState": {"state": "Unknown", "reason": ""},
        })


def test_service_state_body_null_reason_fails():
    """§2.4.2: serviceState.reason MUST be a string, never null."""
    with pytest.raises(AssertionError):
        assert_service_state_notify_body({
            "service": "lvf.psap.allegheny.pa.us",
            "name": "LVF",
            "domain": "lvf.psap.allegheny.pa.us",
            "serviceState": {"state": "Normal", "reason": None},
        })


def test_service_state_body_absent_reason_fails():
    """§2.4.2: serviceState.reason is MANDATORY (even if empty)."""
    with pytest.raises(AssertionError, match="reason"):
        assert_service_state_notify_body({
            "service": "lvf.psap.allegheny.pa.us",
            "name": "LVF",
            "domain": "lvf.psap.allegheny.pa.us",
            "serviceState": {"state": "Normal"},
        })


def test_service_state_body_invalid_posture_value_fails():
    with pytest.raises(AssertionError, match="registry"):
        assert_service_state_notify_body({
            "service": "lvf.psap.allegheny.pa.us",
            "name": "LVF",
            "domain": "lvf.psap.allegheny.pa.us",
            "serviceState": {"state": "Normal", "reason": ""},
            "securityPosture": {"posture": "Purple"},
        })


# ---------------------------------------------------------------------------
# LogEvent prologue assertions (§4.12.3.1)
# ---------------------------------------------------------------------------

def test_log_event_prologue_minimal_passes():
    assert_log_event_prologue({
        "logEventType": "AccessLogEvent",
        "timestamp": "2025-08-21T12:58:03.01-05:00",
        "elementId": "lvf.psap.allegheny.pa.us",
        "agencyId": "psap.allegheny.pa.us",
    })


def test_log_event_prologue_with_call_id_passes():
    assert_log_event_prologue({
        "logEventType": "CallStartLogEvent",
        "timestamp": "2025-08-21T12:58:03.01-05:00",
        "elementId": "lvf.psap.allegheny.pa.us",
        "agencyId": "psap.allegheny.pa.us",
        "callId": "urn:emergency:uid:callid:a4b7f2",
    })


def test_log_event_prologue_missing_log_event_type_fails():
    with pytest.raises(AssertionError, match="logEventType"):
        assert_log_event_prologue({
            "timestamp": "2025-08-21T12:58:03.01-05:00",
            "elementId": "lvf.psap.allegheny.pa.us",
            "agencyId": "psap.allegheny.pa.us",
        })


def test_log_event_prologue_bad_timestamp_fails():
    with pytest.raises(AssertionError):
        assert_log_event_prologue({
            "logEventType": "AccessLogEvent",
            "timestamp": "2025-08-21T12:58:03Z",
            "elementId": "lvf.psap.allegheny.pa.us",
            "agencyId": "psap.allegheny.pa.us",
        })


def test_log_event_prologue_null_conditional_fails():
    """§4.12.3.1: conditional fields must be absent, not null."""
    with pytest.raises(AssertionError, match="absent"):
        assert_log_event_prologue({
            "logEventType": "AccessLogEvent",
            "timestamp": "2025-08-21T12:58:03.01-05:00",
            "elementId": "lvf.psap.allegheny.pa.us",
            "agencyId": "psap.allegheny.pa.us",
            "callId": None,
        })


# ---------------------------------------------------------------------------
# NTP assertion (§2.2)
# ---------------------------------------------------------------------------

def test_ntp_reporting_healthy_client_passes():
    assert_ntp_reporting(_FakeNtpClient())


def test_ntp_reporting_none_fails():
    with pytest.raises(AssertionError, match="None"):
        assert_ntp_reporting(None)


def test_ntp_reporting_no_is_healthy_attr_fails():
    class _NoAttr:
        pass
    with pytest.raises(AssertionError, match="is_healthy"):
        assert_ntp_reporting(_NoAttr())


# ---------------------------------------------------------------------------
# Full conformance suite — assert_core_conformance against test FE
# ---------------------------------------------------------------------------

def test_assert_core_conformance_passes_for_minimal_fe():
    """assert_core_conformance MUST pass for a correctly-wired FE."""
    app = _make_fe_app()
    assert_core_conformance(app, _identity())


def test_assert_core_conformance_passes_with_security_posture_enabled():
    """assert_core_conformance must pass when security posture is opted in."""
    app = _make_fe_app(supports_security_posture=True)
    assert_core_conformance(app, _identity())


def test_assert_core_conformance_wrong_identity_fails():
    """assert_core_conformance must fail if the identity passed does not match the app."""
    wrong = ElementIdentity(
        element_id="wrong.psap.allegheny.pa.us",
        agency_id="psap.allegheny.pa.us",
        agent_id="dispatcher1",
        service_id="wrong.psap.allegheny.pa.us",
        service_name="LVF",
    )
    app = _make_fe_app()
    with pytest.raises(AssertionError, match="elementId"):
        assert_core_conformance(app, wrong)
