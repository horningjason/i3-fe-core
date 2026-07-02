"""Tests for logging/logevent.py — §4.12.3.1 prologue fields and serializer."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

import pytest

from i3_fe_core.logging.logevent import (
    LogEventPrologue,
    prologue_to_dict,
    to_i3_json_key,
)
from i3_fe_core.time.timestamps import format_i3, now_i3


# ---------------------------------------------------------------------------
# to_i3_json_key — camelCase converter
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("snake, expected", [
    ("log_event_type",             "logEventType"),
    ("timestamp",                  "timestamp"),
    ("element_id",                 "elementId"),
    ("agency_id",                  "agencyId"),
    ("client_assigned_identifier", "clientAssignedIdentifier"),
    ("agency_agent_id",            "agencyAgentId"),
    ("agency_position_id",         "agencyPositionId"),
    ("call_id",                    "callId"),
    ("incident_id",                "incidentId"),
    ("call_id_sip",                "callIdSIP"),   # SIP must be ALL-CAPS
    ("ip_address_port",            "ipAddressPort"),
    ("extension",                  "extension"),
])
def test_to_i3_json_key_mapping(snake: str, expected: str):
    assert to_i3_json_key(snake) == expected


def test_sip_abbreviation_is_uppercase():
    """callIdSIP — SIP must NOT be 'Sip' (§4.12.3.1 field name)."""
    assert to_i3_json_key("call_id_sip") == "callIdSIP"
    assert "Sip" not in to_i3_json_key("call_id_sip")


# ---------------------------------------------------------------------------
# LogEventPrologue — dataclass construction
# ---------------------------------------------------------------------------

def test_prologue_requires_log_event_type():
    with pytest.raises(TypeError):
        LogEventPrologue()  # type: ignore[call-arg]


def test_prologue_defaults_all_optional_fields_to_none():
    p = LogEventPrologue(log_event_type="TestEvent")
    assert p.timestamp is None
    assert p.element_id is None
    assert p.agency_id is None
    assert p.client_assigned_identifier is None
    assert p.agency_position_id is None
    assert p.agency_agent_id is None
    assert p.call_id is None
    assert p.incident_id is None
    assert p.call_id_sip is None
    assert p.ip_address_port is None
    assert p.extension == []


# ---------------------------------------------------------------------------
# prologue_to_dict — MANDATORY fields present
# ---------------------------------------------------------------------------

def _stamped_prologue(**kwargs) -> LogEventPrologue:
    """Helper: build a prologue with timestamp/elementId/agencyId filled in."""
    p = LogEventPrologue(log_event_type="TestEvent", **kwargs)
    p.timestamp = now_i3()
    p.element_id = "ecrf.psap.allegheny.pa.us"
    p.agency_id = "psap.allegheny.pa.us"
    return p


def test_mandatory_fields_present():
    body = prologue_to_dict(_stamped_prologue())
    assert "logEventType" in body
    assert "timestamp" in body
    assert "elementId" in body
    assert "agencyId" in body


def test_log_event_type_value():
    body = prologue_to_dict(_stamped_prologue())
    assert body["logEventType"] == "TestEvent"


def test_element_id_value():
    body = prologue_to_dict(_stamped_prologue())
    assert body["elementId"] == "ecrf.psap.allegheny.pa.us"


def test_agency_id_value():
    body = prologue_to_dict(_stamped_prologue())
    assert body["agencyId"] == "psap.allegheny.pa.us"


def test_timestamp_is_string():
    body = prologue_to_dict(_stamped_prologue())
    assert isinstance(body["timestamp"], str)


def test_timestamp_has_offset():
    """§2.3: timestamp must always have an explicit ±HH:MM offset."""
    body = prologue_to_dict(_stamped_prologue())
    ts = body["timestamp"]
    assert "+" in ts or (ts.count("-") >= 3)  # offset present


# ---------------------------------------------------------------------------
# prologue_to_dict — absent OPTIONAL/CONDITIONAL fields omitted
# ---------------------------------------------------------------------------

def test_absent_optional_fields_omitted():
    body = prologue_to_dict(_stamped_prologue())
    assert "clientAssignedIdentifier" not in body
    assert "agencyPositionId" not in body


def test_absent_conditional_fields_omitted():
    body = prologue_to_dict(_stamped_prologue())
    assert "agencyAgentId" not in body
    assert "callId" not in body
    assert "incidentId" not in body
    assert "callIdSIP" not in body
    assert "ipAddressPort" not in body


def test_empty_extension_omitted():
    p = _stamped_prologue()
    assert p.extension == []
    body = prologue_to_dict(p)
    assert "extension" not in body


# ---------------------------------------------------------------------------
# prologue_to_dict — OPTIONAL/CONDITIONAL fields present when set
# ---------------------------------------------------------------------------

def test_client_assigned_identifier_included_when_set():
    p = _stamped_prologue()
    p.client_assigned_identifier = "client-ref-001"
    body = prologue_to_dict(p)
    assert body["clientAssignedIdentifier"] == "client-ref-001"


def test_agency_agent_id_included_when_set():
    p = _stamped_prologue()
    p.agency_agent_id = "agent1.psap.allegheny.pa.us"
    body = prologue_to_dict(p)
    assert body["agencyAgentId"] == "agent1.psap.allegheny.pa.us"


def test_call_id_included_when_set():
    p = _stamped_prologue()
    p.call_id = "urn:emergency:uid:callid:abc123"
    body = prologue_to_dict(p)
    assert body["callId"] == "urn:emergency:uid:callid:abc123"


def test_incident_id_included_when_set():
    p = _stamped_prologue()
    p.incident_id = "urn:emergency:uid:incidentid:xyz789"
    body = prologue_to_dict(p)
    assert body["incidentId"] == "urn:emergency:uid:incidentid:xyz789"


def test_call_id_sip_included_as_callIdSIP():
    """callIdSIP must appear with SIP in all-caps in the emitted dict."""
    p = _stamped_prologue()
    p.call_id_sip = "abc@sip.example.com"
    body = prologue_to_dict(p)
    assert "callIdSIP" in body
    assert body["callIdSIP"] == "abc@sip.example.com"
    assert "callIdSip" not in body  # wrong capitalisation must not appear


def test_ip_address_port_included_when_set():
    p = _stamped_prologue()
    p.ip_address_port = "192.0.2.1:5060"
    body = prologue_to_dict(p)
    assert body["ipAddressPort"] == "192.0.2.1:5060"


def test_extension_included_when_non_empty():
    p = _stamped_prologue()
    p.extension = [{"vendor": "acme", "value": 42}]
    body = prologue_to_dict(p)
    assert body["extension"] == [{"vendor": "acme", "value": 42}]


# ---------------------------------------------------------------------------
# Subclass fields serialized too
# ---------------------------------------------------------------------------

def test_subclass_fields_serialized():
    """FE-specific subclasses add extra fields; prologue_to_dict handles them."""

    @dataclasses.dataclass
    class FakeQueryEvent(LogEventPrologue):
        query_id: str = ""
        direction: str = ""

    evt = FakeQueryEvent(
        log_event_type="LostQueryLogEvent",
        query_id="urn:emergency:uid:queryid:q1",
        direction="outgoing",
    )
    evt.timestamp = now_i3()
    evt.element_id = "ecrf.example.com"
    evt.agency_id = "agency.example.com"

    body = prologue_to_dict(evt)
    assert body["queryId"] == "urn:emergency:uid:queryid:q1"
    assert body["direction"] == "outgoing"
    assert body["logEventType"] == "LostQueryLogEvent"
