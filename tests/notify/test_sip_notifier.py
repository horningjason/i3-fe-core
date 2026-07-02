"""Tests for notify/sip_notifier.py — §2.4 SIP SUBSCRIBE/NOTIFY transport."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from i3_fe_core.config.identity import ElementIdentity
from i3_fe_core.notify.sip_notifier import (
    DEFAULT_SUBSCRIPTION_SECONDS,
    MAX_SUBSCRIPTION_SECONDS,
    MIN_SUBSCRIPTION_SECONDS,
    SipNotifier,
    SipSubscribeRequest,
    SipSubscription,
)
from i3_fe_core.runtime.worker import SingleWorkerContext, WorkerContext
from i3_fe_core.state.element_state import (
    EVENT_PACKAGE_NAME as ELEMENT_EVENT_PACKAGE,
    NOTIFY_MIME_TYPE as ELEMENT_MIME_TYPE,
    ElementState,
    ElementStateNotifier,
)
from i3_fe_core.state.service_state import (
    EVENT_PACKAGE_NAME as SERVICE_EVENT_PACKAGE,
    NOTIFY_MIME_TYPE as SERVICE_MIME_TYPE,
    ServiceState,
    ServiceStateNotifier,
)
from i3_fe_core.state.store import InProcessStateStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _identity() -> ElementIdentity:
    return ElementIdentity(
        element_id="ecrf.psap.allegheny.pa.us",
        agency_id="psap.allegheny.pa.us",
        agent_id="dispatcher1",
        service_id="ecrf.psap.allegheny.pa.us",
        service_name="ECRF",
    )


def _make_notifiers(
    *,
    element_min_interval: float = 0.0,
    service_min_interval: float = 0.0,
    supports_security_posture: bool = False,
) -> tuple[ElementStateNotifier, ServiceStateNotifier]:
    e_store = InProcessStateStore()
    s_store = InProcessStateStore()
    element = ElementStateNotifier(
        identity=_identity(),
        store=e_store,
        min_notify_interval=element_min_interval,
    )
    service = ServiceStateNotifier(
        service="ecrf.psap.allegheny.pa.us",
        name="ECRF",
        domain="ecrf.psap.allegheny.pa.us",
        store=s_store,
        min_notify_interval=service_min_interval,
        supports_security_posture=supports_security_posture,
    )
    return element, service


Notification = tuple[SipSubscription, dict[str, Any], str]


def _make_sip(
    element_notifier: ElementStateNotifier,
    service_notifier: ServiceStateNotifier,
    worker_context: WorkerContext | None = None,
) -> tuple[SipNotifier, list[Notification]]:
    sent: list[Notification] = []

    def send_notify(sub: SipSubscription, body: dict, mime: str) -> None:
        sent.append((sub, body, mime))

    sip = SipNotifier(element_notifier, service_notifier, send_notify, worker_context)
    return sip, sent


def _subscribe_element(sip: SipNotifier, **kwargs: Any) -> Any:
    params: dict[str, Any] = {
        "event_package": ELEMENT_EVENT_PACKAGE,
        "subscriber_uri": "sip:subscriber@example.com",
        "call_id": "call-elem-001",
    }
    params.update(kwargs)
    return sip.handle_subscribe(SipSubscribeRequest(**params))


def _subscribe_service(sip: SipNotifier, **kwargs: Any) -> Any:
    params: dict[str, Any] = {
        "event_package": SERVICE_EVENT_PACKAGE,
        "subscriber_uri": "sip:subscriber@example.com",
        "call_id": "call-svc-001",
    }
    params.update(kwargs)
    return sip.handle_subscribe(SipSubscribeRequest(**params))


# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

def test_duration_constants():
    assert MIN_SUBSCRIPTION_SECONDS == 60
    assert MAX_SUBSCRIPTION_SECONDS == 86_400
    assert DEFAULT_SUBSCRIPTION_SECONDS == 3_600


# ---------------------------------------------------------------------------
# §2.4: SUBSCRIBE — event package validation
# ---------------------------------------------------------------------------

def test_unknown_event_package_returns_489():
    e, s = _make_notifiers()
    sip, _ = _make_sip(e, s)
    resp = sip.handle_subscribe(
        SipSubscribeRequest(
            event_package="emergency-UnknownPackage",
            subscriber_uri="sip:sub@example.com",
            call_id="call-bad",
        )
    )
    assert resp.status_code == 489


def test_element_event_package_accepted():
    e, s = _make_notifiers()
    sip, _ = _make_sip(e, s)
    resp = _subscribe_element(sip)
    assert resp.status_code == 200


def test_service_event_package_accepted():
    e, s = _make_notifiers()
    sip, _ = _make_sip(e, s)
    resp = _subscribe_service(sip)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# §2.4: SUBSCRIBE — duration negotiation
# ---------------------------------------------------------------------------

def test_default_duration_when_expires_absent():
    e, s = _make_notifiers()
    sip, _ = _make_sip(e, s)
    resp = _subscribe_element(sip)  # no expires kwarg → default
    assert resp.expires == DEFAULT_SUBSCRIPTION_SECONDS


def test_explicit_valid_duration_accepted():
    e, s = _make_notifiers()
    sip, _ = _make_sip(e, s)
    resp = _subscribe_element(sip, expires=600)
    assert resp.status_code == 200
    assert resp.expires == 600


def test_expires_below_minimum_returns_423():
    """RFC 6665 §4.1.2.1: too-short Expires MUST yield 423 with Min-Expires, not 400."""
    e, s = _make_notifiers()
    sip, _ = _make_sip(e, s)
    resp = _subscribe_element(sip, expires=MIN_SUBSCRIPTION_SECONDS - 1)
    assert resp.status_code == 423
    assert resp.min_expires == MIN_SUBSCRIPTION_SECONDS


def test_expires_exactly_minimum_accepted():
    e, s = _make_notifiers()
    sip, _ = _make_sip(e, s)
    resp = _subscribe_element(sip, expires=MIN_SUBSCRIPTION_SECONDS)
    assert resp.status_code == 200
    assert resp.expires == MIN_SUBSCRIPTION_SECONDS


def test_expires_above_maximum_is_clamped():
    e, s = _make_notifiers()
    sip, _ = _make_sip(e, s)
    resp = _subscribe_element(sip, expires=MAX_SUBSCRIPTION_SECONDS + 9999)
    assert resp.status_code == 200
    assert resp.expires == MAX_SUBSCRIPTION_SECONDS


def test_expires_exactly_maximum_accepted():
    e, s = _make_notifiers()
    sip, _ = _make_sip(e, s)
    resp = _subscribe_element(sip, expires=MAX_SUBSCRIPTION_SECONDS)
    assert resp.status_code == 200
    assert resp.expires == MAX_SUBSCRIPTION_SECONDS


# ---------------------------------------------------------------------------
# §2.4: SUBSCRIBE — unsubscribe (Expires: 0)
# ---------------------------------------------------------------------------

def test_expires_zero_unsubscribes():
    e, s = _make_notifiers()
    sip, sent = _make_sip(e, s)
    _subscribe_element(sip, call_id="call-e-unsub")
    resp = sip.handle_subscribe(
        SipSubscribeRequest(
            event_package=ELEMENT_EVENT_PACKAGE,
            subscriber_uri="sip:sub@example.com",
            call_id="call-e-unsub",
            expires=0,
        )
    )
    assert resp.status_code == 200
    assert resp.expires == 0
    assert "call-e-unsub" not in sip._subscriptions


def test_expires_zero_on_unknown_call_id_returns_200():
    """Unsubscribing a non-existent Call-ID is harmless."""
    e, s = _make_notifiers()
    sip, _ = _make_sip(e, s)
    resp = sip.handle_subscribe(
        SipSubscribeRequest(
            event_package=ELEMENT_EVENT_PACKAGE,
            subscriber_uri="sip:sub@example.com",
            call_id="call-not-found",
            expires=0,
        )
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# §2.4.1 / §2.4.2: initial NOTIFY on SUBSCRIBE
# ---------------------------------------------------------------------------

def test_subscribe_element_triggers_initial_notify_with_correct_mime():
    """Subscribing MUST produce an immediate initial NOTIFY with ElementState MIME type."""
    e, s = _make_notifiers()
    sip, sent = _make_sip(e, s)
    _subscribe_element(sip)

    assert len(sent) == 1
    sub, body, mime = sent[0]
    assert mime == ELEMENT_MIME_TYPE


def test_subscribe_element_initial_notify_body_structure():
    """Initial NOTIFY body MUST have elementId, state; no reason when default (§2.4.1)."""
    e, s = _make_notifiers()
    sip, sent = _make_sip(e, s)
    _subscribe_element(sip)

    _, body, _ = sent[0]
    assert "elementId" in body
    assert body["elementId"] == "ecrf.psap.allegheny.pa.us"
    assert "state" in body
    assert body["state"] == "Normal"
    assert "reason" not in body  # OPTIONAL — absent when empty


def test_subscribe_service_triggers_initial_notify_with_correct_mime():
    """Subscribing MUST produce an immediate initial NOTIFY with ServiceState MIME type."""
    e, s = _make_notifiers()
    sip, sent = _make_sip(e, s)
    _subscribe_service(sip)

    assert len(sent) == 1
    _, body, mime = sent[0]
    assert mime == SERVICE_MIME_TYPE


def test_subscribe_service_initial_notify_body_structure():
    """Initial NOTIFY body MUST have service, name, domain, serviceState (§2.4.2)."""
    e, s = _make_notifiers()
    sip, sent = _make_sip(e, s)
    _subscribe_service(sip)

    _, body, _ = sent[0]
    assert "service" in body
    assert "name" in body
    assert "domain" in body
    assert "serviceState" in body
    assert body["serviceState"]["state"] == "Normal"


# ---------------------------------------------------------------------------
# State-change → NOTIFY fan-out
# ---------------------------------------------------------------------------

def test_element_state_change_delivers_notify():
    e, s = _make_notifiers()
    sip, sent = _make_sip(e, s)
    _subscribe_element(sip)

    sent.clear()  # discard initial NOTIFY
    e.set_state(ElementState.SERVICE_DISRUPTION, "DB pool exhausted")

    assert len(sent) == 1
    _, body, mime = sent[0]
    assert mime == ELEMENT_MIME_TYPE
    assert body["state"] == "ServiceDisruption"
    assert body["reason"] == "DB pool exhausted"


def test_service_state_change_delivers_notify():
    e, s = _make_notifiers()
    sip, sent = _make_sip(e, s)
    _subscribe_service(sip)

    sent.clear()
    s.set_state(ServiceState.OVERLOADED, "high call volume")

    assert len(sent) == 1
    _, body, mime = sent[0]
    assert mime == SERVICE_MIME_TYPE
    assert body["serviceState"]["state"] == "Overloaded"


def test_element_change_does_not_fan_out_to_service_subscribers():
    """Element NOTIFY must never go to service package subscribers (no cross-fan-out)."""
    e, s = _make_notifiers()
    sip, sent = _make_sip(e, s)
    _subscribe_service(sip)
    sent.clear()

    e.set_state(ElementState.DOWN, "hardware failure")
    assert len(sent) == 0


def test_service_change_does_not_fan_out_to_element_subscribers():
    e, s = _make_notifiers()
    sip, sent = _make_sip(e, s)
    _subscribe_element(sip)
    sent.clear()

    s.set_state(ServiceState.UNSTAFFED)
    assert len(sent) == 0


def test_multiple_subscribers_all_receive_notify():
    """Multiple active subscriptions for the same package all get the NOTIFY."""
    e, s = _make_notifiers()
    sip, sent = _make_sip(e, s)

    for i in range(3):
        sip.handle_subscribe(
            SipSubscribeRequest(
                event_package=ELEMENT_EVENT_PACKAGE,
                subscriber_uri=f"sip:sub{i}@example.com",
                call_id=f"call-multi-{i}",
            )
        )
    sent.clear()  # clear initial NOTIFYs

    e.set_state(ElementState.GOING_DOWN)
    assert len(sent) == 3


# ---------------------------------------------------------------------------
# §2.4 + RFC 6446: per-subscription rate filtering (watchdog / coalescing)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rate_limited_subscription_coalesces_rapid_changes():
    """Rapid element-state changes within the rate window must be coalesced."""
    e, s = _make_notifiers()
    sip, sent = _make_sip(e, s)

    sip.handle_subscribe(
        SipSubscribeRequest(
            event_package=ELEMENT_EVENT_PACKAGE,
            subscriber_uri="sip:rl@example.com",
            call_id="call-rl",
            min_notify_interval=0.1,
        )
    )
    # Initial NOTIFY fires immediately (last_notify_mono starts at 0).
    assert len(sent) == 1
    sent.clear()

    # Drive two rapid changes within the 0.1 s window.
    e.set_state(ElementState.OVERLOADED, "first")   # within window → deferred
    e.set_state(ElementState.DOWN, "second")          # coalesced into deferred

    # Timer has not fired yet.
    assert len(sent) == 0

    # Sleep 0.15 s: long enough for the coalescing timer at 0.1 s to fire,
    # but short enough to finish before the watchdog reschedules at 0.2 s.
    await asyncio.sleep(0.15)

    # Exactly one NOTIFY carrying the latest state.
    assert len(sent) == 1
    _, body, mime = sent[0]
    assert body["state"] == "Down"
    assert mime == ELEMENT_MIME_TYPE


@pytest.mark.asyncio
async def test_rate_limited_watchdog_fires_even_without_state_change():
    """After the initial NOTIFY, a watchdog NOTIFY fires at the min interval."""
    e, s = _make_notifiers()
    sip, sent = _make_sip(e, s)

    sip.handle_subscribe(
        SipSubscribeRequest(
            event_package=ELEMENT_EVENT_PACKAGE,
            subscriber_uri="sip:wd@example.com",
            call_id="call-wd",
            min_notify_interval=0.05,
        )
    )
    # Initial NOTIFY fired.
    assert len(sent) == 1

    # No state change — watchdog should still fire after the interval.
    await asyncio.sleep(0.12)

    # At least one watchdog NOTIFY should have fired.
    assert len(sent) >= 2
    # All NOTIFYs carry the current state (Normal).
    for _, body, _ in sent:
        assert body["state"] == "Normal"


@pytest.mark.asyncio
async def test_service_rate_limited_subscription_coalesces():
    """Same rate-filter coalescing behaviour for the ServiceState package."""
    e, s = _make_notifiers()
    sip, sent = _make_sip(e, s)

    sip.handle_subscribe(
        SipSubscribeRequest(
            event_package=SERVICE_EVENT_PACKAGE,
            subscriber_uri="sip:rl-svc@example.com",
            call_id="call-rl-svc",
            min_notify_interval=0.1,
        )
    )
    assert len(sent) == 1
    sent.clear()

    s.set_state(ServiceState.OVERLOADED, "spike")   # within window → deferred
    s.set_state(ServiceState.PARTIAL, "partial")     # coalesced into above

    assert len(sent) == 0
    # Sleep 0.15 s: long enough for the coalescing timer at 0.1 s to fire,
    # but short enough to finish before the watchdog reschedules at 0.2 s.
    await asyncio.sleep(0.15)
    assert len(sent) == 1
    _, body, _ = sent[0]
    assert body["serviceState"]["state"] == "Partial"


# ---------------------------------------------------------------------------
# §2.4.1: notify body uses correct MIME type constants from the state modules
# ---------------------------------------------------------------------------

def test_element_notify_mime_matches_state_module_constant():
    assert ELEMENT_MIME_TYPE == "Application/EmergencyCallData.ElementState+json"


def test_service_notify_mime_matches_state_module_constant():
    assert SERVICE_MIME_TYPE == "Application/EmergencyCallData.ServiceState+json"


# ---------------------------------------------------------------------------
# Process singleton — leader gate (§2.4.1 / §2.4.2)
# ---------------------------------------------------------------------------

def test_start_returns_true_for_single_worker():
    e, s = _make_notifiers()
    sip, _ = _make_sip(e, s, worker_context=SingleWorkerContext())
    result = sip.start()
    assert result is True


def test_start_returns_false_for_non_leader():
    class AlwaysFollower(WorkerContext):
        def is_leader(self) -> bool:
            return False
        def worker_id(self) -> str:
            return "follower-0"

    e, s = _make_notifiers()
    sip, _ = _make_sip(e, s, worker_context=AlwaysFollower())
    result = sip.start()
    assert result is False


def test_start_without_worker_context_always_activates():
    """Without a worker context, the notifier always starts (no gate)."""
    e, s = _make_notifiers()
    sip, _ = _make_sip(e, s)
    assert sip.start() is True


# ---------------------------------------------------------------------------
# Subscription refresh
# ---------------------------------------------------------------------------

def test_refresh_subscription_replaces_existing():
    """Re-sending SUBSCRIBE with same Call-ID refreshes the subscription."""
    e, s = _make_notifiers()
    sip, sent = _make_sip(e, s)

    _subscribe_element(sip, call_id="call-refresh", expires=600)
    first_sub = sip._subscriptions["call-refresh"]

    _subscribe_element(sip, call_id="call-refresh", expires=1200)
    second_sub = sip._subscriptions["call-refresh"]

    # The subscription object is replaced; old one is gone.
    assert second_sub is not first_sub


def test_refresh_sends_initial_notify():
    e, s = _make_notifiers()
    sip, sent = _make_sip(e, s)

    _subscribe_element(sip, call_id="call-refresh")
    _subscribe_element(sip, call_id="call-refresh")

    # Two initial NOTIFYs: one for each SUBSCRIBE.
    assert len(sent) == 2


# ---------------------------------------------------------------------------
# Resilience — failing send_notify does not raise
# ---------------------------------------------------------------------------

def test_failing_send_notify_is_caught():
    e, s = _make_notifiers()

    def exploding_notify(sub, body, mime):
        raise RuntimeError("SIP transport broke")

    sip = SipNotifier(e, s, exploding_notify)
    _subscribe_element(sip)  # initial NOTIFY should not propagate the exception


# ---------------------------------------------------------------------------
# Subscription capacity cap (memory-exhaustion defence)
# ---------------------------------------------------------------------------

def test_subscription_cap_rejects_new_subscriptions_with_503():
    e, s = _make_notifiers()
    sent: list[Notification] = []
    sip = SipNotifier(e, s, lambda *a: sent.append(a), max_subscriptions=2)

    assert _subscribe_element(sip, call_id="cap-1").status_code == 200
    assert _subscribe_element(sip, call_id="cap-2").status_code == 200
    resp = _subscribe_element(sip, call_id="cap-3")
    assert resp.status_code == 503
    assert "cap-3" not in sip._subscriptions


def test_subscription_cap_still_allows_refresh_of_existing():
    e, s = _make_notifiers()
    sip = SipNotifier(e, s, lambda *a: None, max_subscriptions=1)

    assert _subscribe_element(sip, call_id="cap-refresh").status_code == 200
    # At capacity — but refreshing the same Call-ID must still succeed.
    assert _subscribe_element(sip, call_id="cap-refresh", expires=1200).status_code == 200


def test_subscription_cap_frees_slot_after_unsubscribe():
    e, s = _make_notifiers()
    sip = SipNotifier(e, s, lambda *a: None, max_subscriptions=1)

    assert _subscribe_element(sip, call_id="cap-a").status_code == 200
    assert _subscribe_element(sip, call_id="cap-b").status_code == 503
    # Unsubscribe (Expires: 0) frees the slot.
    assert _subscribe_element(sip, call_id="cap-a", expires=0).status_code == 200
    assert _subscribe_element(sip, call_id="cap-b").status_code == 200


# ---------------------------------------------------------------------------
# §5.4 subscriber authorization + Contact-URI validation
# ---------------------------------------------------------------------------

def test_unauthorized_subscriber_gets_403_and_nothing_stored():
    e, s = _make_notifiers()
    sent: list[Notification] = []

    sip = SipNotifier(
        e, s, lambda *a: sent.append(a),
        authorize_subscriber=lambda req: False,
    )
    resp = _subscribe_element(sip, call_id="authz-denied")
    assert resp.status_code == 403
    assert "authz-denied" not in sip._subscriptions
    assert sent == []  # no initial NOTIFY dispatched


def test_authorized_subscriber_accepted():
    e, s = _make_notifiers()
    seen: list[SipSubscribeRequest] = []

    def authorize(req: SipSubscribeRequest) -> bool:
        seen.append(req)  # the wire layer's authz hook receives the full request
        return True

    sip = SipNotifier(e, s, lambda *a: None, authorize_subscriber=authorize)
    resp = _subscribe_element(sip, call_id="authz-ok")
    assert resp.status_code == 200
    assert "authz-ok" in sip._subscriptions
    assert seen and seen[0].call_id == "authz-ok"


def test_unauthorized_subscriber_cannot_unsubscribe_others():
    """Authorization runs before the Expires=0 unsubscribe branch."""
    e, s = _make_notifiers()
    allowed = {"good-caller"}

    sip = SipNotifier(
        e, s, lambda *a: None,
        authorize_subscriber=lambda req: req.call_id in allowed,
    )
    assert _subscribe_element(sip, call_id="good-caller").status_code == 200
    # Attacker (no longer authorized) guesses the Call-ID and tries to tear
    # the subscription down with Expires: 0.
    allowed.clear()
    resp = _subscribe_element(sip, call_id="good-caller", expires=0)
    assert resp.status_code == 403
    assert "good-caller" in sip._subscriptions  # still subscribed


def test_invalid_target_uri_gets_403_and_no_notify():
    e, s = _make_notifiers()
    sent: list[Notification] = []

    sip = SipNotifier(
        e, s, lambda *a: sent.append(a),
        validate_target_uri=lambda uri: uri.endswith(".psap.allegheny.pa.us"),
    )
    resp = _subscribe_element(
        sip, call_id="bad-target", subscriber_uri="sip:attacker@evil.example"
    )
    assert resp.status_code == 403
    assert "bad-target" not in sip._subscriptions
    assert sent == []


def test_valid_target_uri_accepted():
    e, s = _make_notifiers()
    sent: list[Notification] = []

    sip = SipNotifier(
        e, s, lambda *a: sent.append(a),
        validate_target_uri=lambda uri: uri.endswith(".psap.allegheny.pa.us"),
    )
    resp = _subscribe_element(
        sip, call_id="good-target",
        subscriber_uri="sip:esrp@core.psap.allegheny.pa.us",
    )
    assert resp.status_code == 200
    assert len(sent) == 1  # initial NOTIFY


def test_no_hooks_logs_one_time_warning_and_behavior_unchanged(caplog):
    import logging as _logging
    e, s = _make_notifiers()
    sip, sent = _make_sip(e, s)

    with caplog.at_level(_logging.WARNING, logger="i3_fe_core.notify.sip_notifier"):
        assert _subscribe_element(sip, call_id="unguarded-1").status_code == 200
        assert _subscribe_element(sip, call_id="unguarded-2").status_code == 200

    warnings = [
        r for r in caplog.records
        if "authorize_subscriber" in r.message or "§5.4" in r.message
    ]
    assert len(warnings) == 1  # one-time, not per-SUBSCRIBE
    assert len(sent) == 2      # behavior unchanged: both accepted + initial NOTIFYs


def test_hooks_configured_no_unguarded_warning(caplog):
    import logging as _logging
    e, s = _make_notifiers()
    sip = SipNotifier(e, s, lambda *a: None, authorize_subscriber=lambda req: True)

    with caplog.at_level(_logging.WARNING, logger="i3_fe_core.notify.sip_notifier"):
        assert _subscribe_element(sip).status_code == 200

    assert not [r for r in caplog.records if "authorize_subscriber" in r.message]
