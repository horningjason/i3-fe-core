"""Tests for state/element_state.py — §2.4.1 + §10.13."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from i3_fe_core.config.identity import ElementIdentity
from i3_fe_core.state.element_state import (
    ELEMENT_STATE_REGISTRY,
    EVENT_PACKAGE_NAME,
    NOTIFY_MIME_TYPE,
    ElementState,
    ElementStateNotifier,
)
from i3_fe_core.state.store import InProcessStateStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_notifier(min_interval: float = 0.0) -> ElementStateNotifier:
    identity = ElementIdentity(
        element_id="esrp1.state.pa.us",
        agency_id="state.pa.us",
    )
    store = InProcessStateStore()
    return ElementStateNotifier(identity, store, min_notify_interval=min_interval)


# ---------------------------------------------------------------------------
# §10.13 registry — exact value set
# ---------------------------------------------------------------------------

def test_element_state_registry_exact():
    """ElementState enum MUST contain exactly the §10.13 IANA registry values."""
    expected = {
        "Normal",
        "ScheduledMaintenance",
        "ServiceDisruption",
        "Overloaded",
        "GoingDown",
        "Down",
        "Unreachable",
    }
    actual = {e.value for e in ElementState}
    assert actual == expected, (
        f"Extra: {actual - expected}, Missing: {expected - actual}"
    )


def test_element_state_registry_constant_matches_enum():
    assert ELEMENT_STATE_REGISTRY == {e.value for e in ElementState}


def test_element_state_count():
    assert len(ElementState) == 7


# ---------------------------------------------------------------------------
# Module constants (transport layer uses these)
# ---------------------------------------------------------------------------

def test_event_package_name():
    assert EVENT_PACKAGE_NAME == "emergency-ElementState"


def test_notify_mime_type():
    assert NOTIFY_MIME_TYPE == "Application/EmergencyCallData.ElementState+json"


# ---------------------------------------------------------------------------
# get_notify_body — §2.4.1 field requirements
# ---------------------------------------------------------------------------

def test_notify_body_mandatory_fields_present():
    """elementId and state MUST always be present."""
    notifier = _make_notifier()
    body = notifier.get_notify_body()
    assert "elementId" in body
    assert "state" in body


def test_notify_body_element_id_from_identity():
    """elementId MUST come from injected identity, not os.environ."""
    notifier = _make_notifier()
    body = notifier.get_notify_body()
    assert body["elementId"] == "esrp1.state.pa.us"


def test_notify_body_default_state_is_normal():
    notifier = _make_notifier()
    body = notifier.get_notify_body()
    assert body["state"] == "Normal"


def test_notify_body_state_is_string_value():
    """state field must be the registry string (e.g. 'Down'), not enum repr."""
    notifier = _make_notifier()
    notifier.set_state(ElementState.DOWN, "maintenance")
    body = notifier.get_notify_body()
    assert body["state"] == "Down"
    assert isinstance(body["state"], str)


def test_notify_body_reason_omitted_when_empty():
    """reason is OPTIONAL — must not appear when empty (§2.4.1)."""
    notifier = _make_notifier()
    body = notifier.get_notify_body()
    assert "reason" not in body


def test_notify_body_reason_included_when_set():
    """reason is OPTIONAL but present when provided."""
    notifier = _make_notifier()
    notifier.set_state(ElementState.SERVICE_DISRUPTION, "DB pool exhausted")
    body = notifier.get_notify_body()
    assert body["reason"] == "DB pool exhausted"


# ---------------------------------------------------------------------------
# set_state — idempotency and transitions
# ---------------------------------------------------------------------------

def test_set_state_noop_when_unchanged():
    """set_state must be a no-op when state and reason are the same."""
    notifier = _make_notifier()
    received: list[dict] = []
    notifier.subscribe(received.append)

    notifier.set_state(ElementState.NORMAL, "")
    assert received == [], "No transition occurred; no notify should be sent"


def test_set_state_notifies_on_genuine_transition():
    notifier = _make_notifier()
    received: list[dict] = []
    notifier.subscribe(received.append)

    notifier.set_state(ElementState.DOWN, "test")
    assert len(received) == 1
    assert received[0]["state"] == "Down"


def test_set_state_reason_change_triggers_notify():
    """Changing only the reason (same state) must also trigger a notify."""
    notifier = _make_notifier()
    received: list[dict] = []
    notifier.subscribe(received.append)

    notifier.set_state(ElementState.OVERLOADED, "reason-a")
    notifier.set_state(ElementState.OVERLOADED, "reason-b")
    assert len(received) == 2


# ---------------------------------------------------------------------------
# RFC 6446 rate filtering — coalescing
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rate_limit_first_change_is_immediate():
    """The very first state change must always dispatch immediately."""
    notifier = _make_notifier(min_interval=10.0)  # large interval
    received: list[dict] = []
    notifier.subscribe(received.append)

    notifier.set_state(ElementState.OVERLOADED)
    # No await — notification must be synchronous on first call.
    assert len(received) == 1
    assert received[0]["state"] == "Overloaded"


@pytest.mark.asyncio
async def test_rate_limit_coalesces_rapid_changes():
    """Rapid changes within the interval MUST be coalesced to a single NOTIFY."""
    notifier = _make_notifier(min_interval=0.1)
    received: list[dict] = []
    notifier.subscribe(received.append)

    # First change → dispatched immediately (no previous notify).
    notifier.set_state(ElementState.OVERLOADED)
    assert len(received) == 1

    # Rapid subsequent changes — all within the 0.1 s window.
    notifier.set_state(ElementState.SERVICE_DISRUPTION, "settling")
    notifier.set_state(ElementState.NORMAL, "recovered")

    # Nothing dispatched yet — timer is pending.
    assert len(received) == 1

    # Wait for the timer to fire.
    await asyncio.sleep(0.2)

    # Only one coalesced notify, carrying the final state.
    assert len(received) == 2
    assert received[1]["state"] == "Normal"


@pytest.mark.asyncio
async def test_rate_limit_no_double_timer():
    """Many rapid changes must not schedule multiple timers."""
    notifier = _make_notifier(min_interval=0.1)
    received: list[dict] = []
    notifier.subscribe(received.append)

    notifier.set_state(ElementState.OVERLOADED)  # immediate
    for _ in range(10):
        notifier.set_state(ElementState.DOWN, "storm")
        notifier.set_state(ElementState.NORMAL, "back")

    await asyncio.sleep(0.2)

    # Exactly 2 total: one immediate + one deferred (coalesced).
    assert len(received) == 2


def test_rate_limit_falls_back_to_immediate_without_loop():
    """Without a running event loop, set_state must still dispatch immediately."""
    notifier = _make_notifier(min_interval=10.0)  # large interval
    received: list[dict] = []
    notifier.subscribe(received.append)

    # Force a recent "last notify" to put us inside the rate window.
    notifier._last_notify_mono = time.monotonic()

    # No asyncio loop is running here — must fall back to immediate dispatch.
    notifier.set_state(ElementState.DOWN, "no loop")
    assert len(received) == 1
    assert received[0]["state"] == "Down"


# ---------------------------------------------------------------------------
# Multiple subscribers
# ---------------------------------------------------------------------------

def test_multiple_subscribers_all_notified():
    notifier = _make_notifier()
    a: list[dict] = []
    b: list[dict] = []
    notifier.subscribe(a.append)
    notifier.subscribe(b.append)

    notifier.set_state(ElementState.GOING_DOWN)
    assert len(a) == 1
    assert len(b) == 1
    assert a[0] == b[0]


def test_failing_subscriber_does_not_block_others():
    """A callback that raises must not prevent subsequent callbacks from running."""
    notifier = _make_notifier()
    good: list[dict] = []

    def bad_cb(body: dict) -> None:
        raise RuntimeError("boom")

    notifier.subscribe(bad_cb)
    notifier.subscribe(good.append)

    notifier.set_state(ElementState.DOWN)
    assert len(good) == 1
