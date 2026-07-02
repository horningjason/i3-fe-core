"""Tests for state/service_state.py — §2.4.2 + §10.12 + §10.18."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from i3_fe_core.state.service_state import (
    EVENT_PACKAGE_NAME,
    NOTIFY_MIME_TYPE,
    SECURITY_POSTURE_REGISTRY,
    SERVICE_STATE_REGISTRY,
    SecurityPosture,
    ServiceState,
    ServiceStateNotifier,
)
from i3_fe_core.state.store import InProcessStateStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_notifier(
    *,
    service: str = "lvf.psap.allegheny.pa.us",
    name: str = "LVF",
    domain: str = "lvf.psap.allegheny.pa.us",
    service_id: str | None = None,
    min_interval: float = 0.0,
    supports_security_posture: bool = False,
    initial_security_posture: SecurityPosture = SecurityPosture.GREEN,
) -> ServiceStateNotifier:
    store = InProcessStateStore()
    return ServiceStateNotifier(
        service=service,
        name=name,
        domain=domain,
        store=store,
        service_id=service_id,
        min_notify_interval=min_interval,
        supports_security_posture=supports_security_posture,
        initial_security_posture=initial_security_posture,
    )


# ---------------------------------------------------------------------------
# §10.12 registry — exact value set (10 values)
# ---------------------------------------------------------------------------

def test_service_state_registry_exact():
    """ServiceState enum MUST contain exactly the §10.12 IANA registry values."""
    expected = {
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
    }
    actual = {e.value for e in ServiceState}
    assert actual == expected, (
        f"Extra: {actual - expected}, Missing: {expected - actual}"
    )


def test_service_state_count():
    assert len(ServiceState) == 10


def test_service_state_registry_constant_matches_enum():
    assert SERVICE_STATE_REGISTRY == {e.value for e in ServiceState}


# ---------------------------------------------------------------------------
# §10.18 registry — exact value set (4 values)
# ---------------------------------------------------------------------------

def test_security_posture_registry_exact():
    """SecurityPosture enum MUST contain exactly the §10.18 IANA registry values."""
    expected = {"Green", "Yellow", "Orange", "Red"}
    actual = {e.value for e in SecurityPosture}
    assert actual == expected, (
        f"Extra: {actual - expected}, Missing: {expected - actual}"
    )


def test_security_posture_count():
    assert len(SecurityPosture) == 4


def test_security_posture_registry_constant_matches_enum():
    assert SECURITY_POSTURE_REGISTRY == {e.value for e in SecurityPosture}


# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

def test_event_package_name():
    assert EVENT_PACKAGE_NAME == "emergency-ServiceState"


def test_notify_mime_type():
    assert NOTIFY_MIME_TYPE == "Application/EmergencyCallData.ServiceState+json"


# ---------------------------------------------------------------------------
# get_notify_body — §2.4.2 mandatory fields
# ---------------------------------------------------------------------------

def test_notify_body_service_mandatory():
    notifier = _make_notifier(service="foo.example.com")
    body = notifier.get_notify_body()
    assert body["service"] == "foo.example.com"


def test_notify_body_name_mandatory():
    notifier = _make_notifier(name="GCS")
    body = notifier.get_notify_body()
    assert body["name"] == "GCS"


def test_notify_body_domain_mandatory():
    """domain MUST always be present — commonly omitted in implementations (§2.4.2)."""
    notifier = _make_notifier(domain="lvf.example.com")
    body = notifier.get_notify_body()
    assert "domain" in body
    assert body["domain"] == "lvf.example.com"


def test_notify_body_service_state_mandatory():
    notifier = _make_notifier()
    body = notifier.get_notify_body()
    assert "serviceState" in body
    assert "state" in body["serviceState"]
    assert "reason" in body["serviceState"]


def test_notify_body_service_state_defaults():
    notifier = _make_notifier()
    body = notifier.get_notify_body()
    assert body["serviceState"]["state"] == "Normal"
    assert body["serviceState"]["reason"] == ""  # MANDATORY, empty string when no reason


def test_notify_body_reason_is_always_string_not_none():
    """reason in serviceState is MANDATORY — must be "" not absent/null (§2.4.2)."""
    notifier = _make_notifier()
    body = notifier.get_notify_body()
    assert body["serviceState"]["reason"] is not None
    assert isinstance(body["serviceState"]["reason"], str)


def test_notify_body_name_distinct_from_service():
    """name (IANA token) and service (subscribed URI) are distinct fields (§2.4.2)."""
    notifier = _make_notifier(
        service="lvf.psap.allegheny.pa.us",
        name="LVF",
    )
    body = notifier.get_notify_body()
    assert body["name"] == "LVF"
    assert body["service"] == "lvf.psap.allegheny.pa.us"
    # They may be the same string by coincidence but must be separate keys.
    assert "name" in body and "service" in body


# ---------------------------------------------------------------------------
# serviceId — optional, must equal domain when present (§2.4.2 fn.4)
# ---------------------------------------------------------------------------

def test_service_id_absent_when_not_provided():
    notifier = _make_notifier()
    body = notifier.get_notify_body()
    assert "serviceId" not in body


def test_service_id_present_when_provided():
    notifier = _make_notifier(
        domain="lvf.example.com",
        service_id="lvf.example.com",
    )
    body = notifier.get_notify_body()
    assert "serviceId" in body
    assert body["serviceId"] == body["domain"]


def test_service_id_must_equal_domain():
    """serviceId MUST equal domain — constructor must reject mismatches (§2.4.2)."""
    with pytest.raises(ValueError, match="serviceId"):
        _make_notifier(
            domain="lvf.example.com",
            service_id="OTHER.example.com",
        )


# ---------------------------------------------------------------------------
# securityPosture — CONDITIONAL (absent when unsupported, present when opted-in)
# ---------------------------------------------------------------------------

def test_security_posture_absent_when_not_supported():
    """securityPosture must be absent (not null) when the FE doesn't maintain one."""
    notifier = _make_notifier(supports_security_posture=False)
    body = notifier.get_notify_body()
    assert "securityPosture" not in body


def test_security_posture_present_when_opted_in():
    """securityPosture MUST be present when the FE opts in (§2.4.2 CONDITIONAL)."""
    notifier = _make_notifier(supports_security_posture=True)
    body = notifier.get_notify_body()
    assert "securityPosture" in body
    assert body["securityPosture"] is not None


def test_security_posture_default_green_when_no_posture_set():
    """When opted in but no posture set yet, defaults to Green (operating normally)."""
    notifier = _make_notifier(supports_security_posture=True)
    body = notifier.get_notify_body()
    assert body["securityPosture"]["posture"] == "Green"


def test_initial_security_posture_non_default():
    """A non-default initial_security_posture is carried in the first NOTIFY body."""
    notifier = _make_notifier(
        supports_security_posture=True,
        initial_security_posture=SecurityPosture.YELLOW,
    )
    body = notifier.get_notify_body()
    assert body["securityPosture"]["posture"] == "Yellow"


def test_security_posture_posture_field_mandatory():
    notifier = _make_notifier(supports_security_posture=True)
    notifier.set_security_posture(SecurityPosture.YELLOW, "scan elevated")
    body = notifier.get_notify_body()
    assert "posture" in body["securityPosture"]


def test_security_posture_reason_included_when_set():
    notifier = _make_notifier(supports_security_posture=True)
    notifier.set_security_posture(SecurityPosture.ORANGE, "active attack pattern")
    body = notifier.get_notify_body()
    assert body["securityPosture"]["reason"] == "active attack pattern"


def test_security_posture_reason_omitted_when_empty():
    """reason inside securityPosture is OPTIONAL — must not appear when empty."""
    notifier = _make_notifier(supports_security_posture=True)
    notifier.set_security_posture(SecurityPosture.YELLOW, "")
    body = notifier.get_notify_body()
    assert "reason" not in body["securityPosture"]


def test_security_posture_value_is_registry_string():
    notifier = _make_notifier(supports_security_posture=True)
    notifier.set_security_posture(SecurityPosture.RED)
    body = notifier.get_notify_body()
    assert body["securityPosture"]["posture"] == "Red"
    assert isinstance(body["securityPosture"]["posture"], str)


# ---------------------------------------------------------------------------
# set_state — idempotency and transitions
# ---------------------------------------------------------------------------

def test_set_state_noop_when_unchanged():
    notifier = _make_notifier()
    received: list[dict] = []
    notifier.subscribe(received.append)

    notifier.set_state(ServiceState.NORMAL, "")
    assert received == []


def test_set_state_notifies_on_transition():
    notifier = _make_notifier()
    received: list[dict] = []
    notifier.subscribe(received.append)

    notifier.set_state(ServiceState.DOWN, "DB offline")
    assert len(received) == 1
    assert received[0]["serviceState"]["state"] == "Down"


def test_set_state_preserves_security_posture():
    """set_state must not clear an existing security posture."""
    notifier = _make_notifier(supports_security_posture=True)
    notifier.set_security_posture(SecurityPosture.YELLOW, "scan")
    notifier.set_state(ServiceState.PARTIAL, "degraded")

    body = notifier.get_notify_body()
    assert body["securityPosture"]["posture"] == "Yellow"


def test_set_security_posture_noop_when_unchanged():
    """GREEN is seeded at construction; repeated calls with the same value are no-ops."""
    notifier = _make_notifier(supports_security_posture=True)
    received: list[dict] = []
    notifier.subscribe(received.append)

    notifier.set_security_posture(SecurityPosture.GREEN, "")
    notifier.set_security_posture(SecurityPosture.GREEN, "")
    assert len(received) == 0  # both calls match the seeded value — idempotent


# ---------------------------------------------------------------------------
# RFC 6446 rate filtering — same pattern as ElementStateNotifier
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rate_limit_first_change_is_immediate():
    notifier = _make_notifier(min_interval=10.0)
    received: list[dict] = []
    notifier.subscribe(received.append)

    notifier.set_state(ServiceState.OVERLOADED)
    assert len(received) == 1


@pytest.mark.asyncio
async def test_rate_limit_coalesces_rapid_changes():
    notifier = _make_notifier(min_interval=0.1)
    received: list[dict] = []
    notifier.subscribe(received.append)

    notifier.set_state(ServiceState.OVERLOADED)        # immediate
    assert len(received) == 1

    notifier.set_state(ServiceState.DOWN, "worse")     # deferred
    notifier.set_state(ServiceState.NORMAL, "back")    # coalesced into above

    assert len(received) == 1
    await asyncio.sleep(0.2)
    assert len(received) == 2
    assert received[1]["serviceState"]["state"] == "Normal"


def test_rate_limit_falls_back_without_loop():
    notifier = _make_notifier(min_interval=10.0)
    received: list[dict] = []
    notifier.subscribe(received.append)

    notifier._last_notify_mono = time.monotonic()
    notifier.set_state(ServiceState.DOWN, "no loop fallback")
    assert len(received) == 1


# ---------------------------------------------------------------------------
# Aggregate seam — external aggregator drives state
# ---------------------------------------------------------------------------

def test_aggregate_set_state_drives_notifier():
    """An external aggregator can call set_state directly without this process
    owning the business logic (§2.4.2 aggregate seam)."""
    notifier = _make_notifier()
    received: list[dict] = []
    notifier.subscribe(received.append)

    # Simulate external aggregator driving state
    notifier.set_state(ServiceState.OVERLOADED, "aggregated from 3/3 nodes overloaded")
    assert received[0]["serviceState"]["state"] == "Overloaded"
    assert "aggregated" in received[0]["serviceState"]["reason"]


# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------

def test_failing_subscriber_does_not_block_others():
    notifier = _make_notifier()
    good: list[dict] = []

    def bad_cb(body: dict) -> None:
        raise RuntimeError("boom")

    notifier.subscribe(bad_cb)
    notifier.subscribe(good.append)

    notifier.set_state(ServiceState.DOWN)
    assert len(good) == 1
