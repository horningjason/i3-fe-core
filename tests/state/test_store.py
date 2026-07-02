"""Tests for state/store.py — §2.4.1 ElementState, §2.4.2 ServiceState."""

import pytest

from i3_fe_core.state.store import (
    ElementState,
    ElementStateBundle,
    InProcessStateStore,
    SecurityPosture,
    SecurityPostureBundle,
    ServiceState,
    ServiceStateBundle,
    StateStore,
)


# ---------------------------------------------------------------------------
# Default startup values (universal baseline from the prompt)
# ---------------------------------------------------------------------------

def test_element_state_default():
    store = InProcessStateStore()
    bundle = store.get_element_state()
    assert bundle.state == ElementState.NORMAL
    assert bundle.reason == ""  # empty string, never None


def test_service_state_default():
    store = InProcessStateStore()
    bundle = store.get_service_state()
    assert bundle.state == ServiceState.NORMAL
    assert bundle.reason == ""  # MANDATORY field, empty string per §2.4.2
    assert bundle.security_posture is None  # absent until FE opts in


# ---------------------------------------------------------------------------
# get/set round-trips
# ---------------------------------------------------------------------------

def test_set_element_state():
    store = InProcessStateStore()
    new_bundle = ElementStateBundle(
        state=ElementState.SERVICE_DISRUPTION,
        reason="Database connection pool exhausted",
    )
    store.set_element_state(new_bundle)
    result = store.get_element_state()
    assert result.state == ElementState.SERVICE_DISRUPTION
    assert result.reason == "Database connection pool exhausted"


def test_set_service_state_without_security_posture():
    store = InProcessStateStore()
    store.set_service_state(
        ServiceStateBundle(state=ServiceState.PARTIAL, reason="Cache miss rate elevated")
    )
    result = store.get_service_state()
    assert result.state == ServiceState.PARTIAL
    assert result.reason == "Cache miss rate elevated"
    assert result.security_posture is None


def test_set_service_state_with_security_posture():
    store = InProcessStateStore()
    posture = SecurityPostureBundle(
        posture=SecurityPosture.YELLOW,
        reason="Elevated SIP scan activity",
    )
    store.set_service_state(
        ServiceStateBundle(
            state=ServiceState.NORMAL,
            reason="",
            security_posture=posture,
        )
    )
    result = store.get_service_state()
    assert result.security_posture is not None
    assert result.security_posture.posture == SecurityPosture.YELLOW


# ---------------------------------------------------------------------------
# Stores are independent
# ---------------------------------------------------------------------------

def test_element_and_service_stores_are_independent():
    store = InProcessStateStore()
    store.set_element_state(ElementStateBundle(state=ElementState.DOWN))
    # Service state must be unaffected.
    assert store.get_service_state().state == ServiceState.NORMAL


# ---------------------------------------------------------------------------
# IANA registry values (§10.13, §10.12, §10.18)
# ---------------------------------------------------------------------------

def test_element_state_enum_values():
    values = {v.value for v in ElementState}
    assert "Normal" in values
    assert "ScheduledMaintenance" in values
    assert "ServiceDisruption" in values
    assert "Overloaded" in values
    assert "GoingDown" in values
    assert "Down" in values
    assert "Unreachable" in values


def test_service_state_enum_values():
    values = {v.value for v in ServiceState}
    assert "Normal" in values
    assert "Unstaffed" in values
    assert "ScheduledMaintenanceDown" in values
    assert "ScheduledMaintenanceAvailable" in values
    assert "MajorIncidentInProgress" in values
    assert "Partial" in values
    assert "Overloaded" in values
    assert "GoingDown" in values
    assert "Down" in values
    assert "Unreachable" in values


def test_security_posture_enum_values():
    values = {v.value for v in SecurityPosture}
    assert "Green" in values
    assert "Yellow" in values
    assert "Orange" in values
    assert "Red" in values


# ---------------------------------------------------------------------------
# InProcessStateStore is a StateStore
# ---------------------------------------------------------------------------

def test_is_state_store_subclass():
    store = InProcessStateStore()
    assert isinstance(store, StateStore)
