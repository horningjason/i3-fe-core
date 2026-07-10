"""LogEvent prologue — §4.12.3.1 common fields for all i3 LogEvent types.

The Logging Service stores LogEvents as a JWS (§5.10).  Every LogEvent
regardless of type carries the fields defined here as a common prologue.
FE-specific event types (e.g. LostQueryLogEvent in the ECRF repo) MUST
subclass LogEventPrologue and add their own fields.  The core package owns
only the shared prologue; it never imports FE-specific subtypes.

Serialization
-------------
``prologue_to_dict()`` converts a LogEventPrologue (or subclass) to a
JSON-serializable dict using camelCase keys as required by the standard.
The converter:
  - drops fields whose value is None (OPTIONAL / CONDITIONAL absent fields
    must not appear in the JSON payload)
  - drops ``extension`` when the list is empty
  - converts the datetime ``timestamp`` to an i3 Timestamp string (§2.3)
  - maps ``callIdSIP`` with SIP in all-caps (not 'Sip') — see
    ``to_i3_json_key()``

Note on ``serviceId``
---------------------
``serviceId`` is NOT a prologue field (§4.12.3.1). Do not add it here.
Service-specific event subtypes may carry it as an additional member.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


# ---------------------------------------------------------------------------
# camelCase converter with i3-specific abbreviation rules
# ---------------------------------------------------------------------------

# Segments that must appear in ALL-CAPS when they are not the first segment
# of a snake_case name.  Derived from inspection of §4.12.3.1 field names.
_UPPERCASE_SEGMENTS: frozenset[str] = frozenset({"SIP", "URI"})


def to_i3_json_key(snake: str) -> str:
    """Convert a snake_case field name to the camelCase JSON key used in i3.

    Special-case: segments that are known all-uppercase abbreviations in the
    i3 standard (SIP, URI) are emitted in upper-case rather than capitalised.

    Examples::

        to_i3_json_key("log_event_type")   → "logEventType"
        to_i3_json_key("call_id_sip")      → "callIdSIP"
        to_i3_json_key("ip_address_port")  → "ipAddressPort"
        to_i3_json_key("agency_id")        → "agencyId"
    """
    parts = snake.split("_")
    result = [parts[0]]  # first segment stays lowercase
    for part in parts[1:]:
        upper = part.upper()
        result.append(upper if upper in _UPPERCASE_SEGMENTS else part.capitalize())
    return "".join(result)


# ---------------------------------------------------------------------------
# LogEventPrologue
# ---------------------------------------------------------------------------

@dataclass
class LogEventPrologue:
    """Common prologue carried by every i3 LogEvent (§4.12.3.1).

    Field conditions follow the standard:
        MANDATORY   — always present; LoggingClient fills in elementId, agencyId,
                      timestamp at emit time.
        OPTIONAL    — set to None to omit from JSON.
        CONDITIONAL — set to None when the condition is not met (e.g. callId is
                      None when no call is associated with this event).

    Usage::

        event = LogEventPrologue(log_event_type="ElementStateChangeLogEvent")
        event.call_id = call_id  # only when call-associated
        body = logging_client.emit(event)
    """

    # MANDATORY — caller supplies the event type; infrastructure fills the rest.
    log_event_type: str

    # Infrastructure-managed MANDATORY fields: LoggingClient fills these in at
    # emit time from the injected ElementIdentity and now_i3() — callers need
    # not set them.
    timestamp: datetime | None = None  # will be stamped at emit time
    element_id: str | None = None      # from ElementIdentity.element_id
    agency_id: str | None = None       # from ElementIdentity.agency_id

    # OPTIONAL
    client_assigned_identifier: str | None = None
    agency_position_id: str | None = None

    # CONDITIONAL
    agency_agent_id: str | None = None   # required when traceable to an agent
    call_id: str | None = None           # required when call-associated
    incident_id: str | None = None       # required when incident-associated
    call_id_sip: str | None = None       # required when SIP-call-associated
    ip_address_port: str | None = None   # required when peer identity is known

    # OPTIONAL, 0 or more times
    extension: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Serializer
# ---------------------------------------------------------------------------

def prologue_to_dict(event: LogEventPrologue) -> dict[str, Any]:
    """Serialize *event* to a camelCase JSON-ready dict.

    Rules (§4.12.3.1):
      - None-valued fields are dropped (absent OPTIONAL / CONDITIONAL).
      - ``extension`` is dropped when the list is empty.
      - ``timestamp`` is formatted as an i3 Timestamp string (§2.3).
      - Field names are converted via ``to_i3_json_key()``.

    Subclass fields beyond the prologue are also serialized, provided they
    follow the same snake_case naming convention.
    """
    from i3_fe_core.time.timestamps import format_i3  # avoid circular at module level

    result: dict[str, Any] = {}
    for f in dataclasses.fields(event):
        value = getattr(event, f.name)
        if value is None:
            continue
        if f.name == "extension" and not value:
            continue
        if f.name == "timestamp":
            value = format_i3(value)
        result[to_i3_json_key(f.name)] = value
    return result


# ---------------------------------------------------------------------------
# FE-generic LogEvent subtypes (§4.12.3)
# ---------------------------------------------------------------------------

@dataclass
class ElementStateChangeLogEvent(LogEventPrologue):
    """§4.12.3 — logged when an element sends/receives an ElementState
    change notification. affected_element_id is OPTIONAL (omit) when the
    emitting element is itself the element whose state changed."""

    log_event_type: str = "ElementStateChangeLogEvent"
    notification_contents: dict[str, Any] | None = None
    state_change_notification_contents: dict[str, Any] | None = None
    affected_element_id: str | None = None
    direction: str | None = None            # "incoming" | "outgoing"


@dataclass
class ServiceStateChangeLogEvent(LogEventPrologue):
    """§4.12.3 — logged when a Service sends/receives a ServiceState
    change (including Security Posture)."""

    log_event_type: str = "ServiceStateChangeLogEvent"
    new_state: str | None = None
    new_security_posture: str | None = None
    affected_service_identifier: str | None = None
    direction: str | None = None            # "incoming" | "outgoing"


@dataclass
class SubscribeLogEvent(LogEventPrologue):
    """§4.12.3 — logged for every processed SUBSCRIBE on any defined
    Event Package. subscription_id correlates transactions on one
    subscription (urn:emergency:uid:subid:<globally-unique-id>)."""

    log_event_type: str = "SubscribeLogEvent"
    package: str | None = None
    peer: str | None = None
    parameter: list[dict[str, Any]] | None = None
    expiration: str | None = None
    response: int | None = None
    purpose: str | None = None              # "initial" | "refresh" | "terminate"
    direction: str | None = None            # "incoming" | "outgoing"
    subscription_id: str | None = None


@dataclass
class DiscrepancyReportLogEvent(LogEventPrologue):
    """§4.12.3 — logged by any element that sends/receives a Discrepancy
    Report or an update to one. `type` is the DR web-service function name
    (DiscrepancyReportRequest, DiscrepancyResolution, etc.). The field is
    named `type` deliberately so it serializes to the STA-010 "type"
    member."""

    log_event_type: str = "DiscrepancyReportLogEvent"
    contents: dict[str, Any] | None = None
    type: str | None = None
    direction: str | None = None            # "incoming" | "outgoing"


@dataclass
class VersionsLogEvent(LogEventPrologue):
    """§4.12.3 — logged by an FE for the Versions response it RECEIVES for
    a Versions request it issued (client side), on the initial request or
    when the response changes. Dormant generic type: the Versions
    entrypoint does NOT emit this on inbound calls; client-side emission
    is wired by the consuming FE. `contents` carries the received Versions
    response body (including the code-set fingerprint)."""

    log_event_type: str = "VersionsLogEvent"
    contents: dict[str, Any] | None = None
    direction: str | None = None            # "incoming"
