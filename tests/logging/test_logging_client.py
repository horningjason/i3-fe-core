"""Tests for logging/logging_client.py — LoggingClient emit behaviour."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from i3_fe_core.config.identity import ElementIdentity
from i3_fe_core.logging.logevent import LogEventPrologue
from i3_fe_core.logging.logging_client import LoggingClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _identity(
    element_id: str = "ecrf.psap.allegheny.pa.us",
    agency_id: str = "psap.allegheny.pa.us",
) -> ElementIdentity:
    return ElementIdentity(
        element_id=element_id,
        agency_id=agency_id,
        agent_id="dispatcher1",
        service_id="ecrf.psap.allegheny.pa.us",
        service_name="ECRF",
    )


def _make_client(
    identity: ElementIdentity | None = None,
    logging_service_uri: str | None = None,
    http_client: httpx.AsyncClient | None = None,
    sign_payload=None,
) -> LoggingClient:
    return LoggingClient(
        identity=identity or _identity(),
        logging_service_uri=logging_service_uri,
        http_client=http_client,
        sign_payload=sign_payload,
    )


class _FakeHttpClient:
    """Records POST calls without touching the network."""

    def __init__(self, status_code: int = 201) -> None:
        self.posts: list[dict[str, Any]] = []
        self._status_code = status_code

    async def post(self, url: str, *, content: bytes, headers: dict) -> httpx.Response:
        self.posts.append({"url": url, "content": content, "headers": headers})
        return httpx.Response(self._status_code)


# ---------------------------------------------------------------------------
# emit() — mandatory field population
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_emit_sets_element_id_from_identity():
    client = _make_client(identity=_identity(element_id="ecrf.test.example.com"))
    body = await client.emit(LogEventPrologue(log_event_type="TestEvent"))
    assert body["elementId"] == "ecrf.test.example.com"


@pytest.mark.asyncio
async def test_emit_sets_agency_id_from_identity():
    client = _make_client(identity=_identity(agency_id="agency.test.example.com"))
    body = await client.emit(LogEventPrologue(log_event_type="TestEvent"))
    assert body["agencyId"] == "agency.test.example.com"


@pytest.mark.asyncio
async def test_emit_stamps_timestamp():
    client = _make_client()
    body = await client.emit(LogEventPrologue(log_event_type="TestEvent"))
    assert "timestamp" in body
    assert isinstance(body["timestamp"], str)
    assert len(body["timestamp"]) > 10


@pytest.mark.asyncio
async def test_emit_includes_log_event_type():
    client = _make_client()
    body = await client.emit(LogEventPrologue(log_event_type="ElementStateChangeLogEvent"))
    assert body["logEventType"] == "ElementStateChangeLogEvent"


@pytest.mark.asyncio
async def test_emit_overrides_caller_supplied_element_id():
    """emit() must override elementId from identity, not accept caller value."""
    client = _make_client(identity=_identity(element_id="correct.example.com"))
    event = LogEventPrologue(log_event_type="TestEvent")
    event.element_id = "wrong.example.com"
    body = await client.emit(event)
    assert body["elementId"] == "correct.example.com"


# ---------------------------------------------------------------------------
# emit() — absent CONDITIONAL fields
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_emit_omits_absent_conditional_fields():
    client = _make_client()
    body = await client.emit(LogEventPrologue(log_event_type="ElementStateChangeLogEvent"))
    for absent in ("callId", "incidentId", "callIdSIP", "ipAddressPort", "agencyAgentId"):
        assert absent not in body


@pytest.mark.asyncio
async def test_emit_includes_call_id_when_set():
    client = _make_client()
    event = LogEventPrologue(log_event_type="CallStartLogEvent")
    event.call_id = "urn:emergency:uid:callid:test001"
    body = await client.emit(event)
    assert body["callId"] == "urn:emergency:uid:callid:test001"


@pytest.mark.asyncio
async def test_emit_includes_call_id_sip_as_callIdSIP():
    client = _make_client()
    event = LogEventPrologue(log_event_type="CallSignalingMessageLogEvent")
    event.call_id_sip = "abc123@sip.example.com"
    body = await client.emit(event)
    assert "callIdSIP" in body
    assert body["callIdSIP"] == "abc123@sip.example.com"


# ---------------------------------------------------------------------------
# emit() — stdlib logging side-effect
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_emit_logs_to_stdlib_logging(caplog: pytest.LogCaptureFixture):
    client = _make_client()
    with caplog.at_level(logging.INFO, logger="i3_fe_core.logging.logging_client"):
        await client.emit(LogEventPrologue(log_event_type="TestEvent"))
    assert any("LogEvent" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# emit() — agencyId warning
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_empty_agency_id_emits_warning(caplog: pytest.LogCaptureFixture):
    """Empty agencyId MUST produce a warning (§4.12.3.1 conformance note)."""
    ident = ElementIdentity(
        element_id="ecrf.test.example.com",
        agency_id="agency.test.example.com",  # valid for identity
        agent_id="agent1",
        service_id="ecrf.test.example.com",
        service_name="ECRF",
    )
    client = _make_client(identity=ident)
    event = LogEventPrologue(log_event_type="TestEvent")
    # Simulate identity having empty agency_id (monkeypatching after construction)
    client._identity = ElementIdentity(
        element_id="ecrf.test.example.com",
        agency_id="agency.test.example.com",
        agent_id="agent1",
        service_id="ecrf.test.example.com",
        service_name="ECRF",
    )
    # Force empty via direct attribute override at emit time
    original_agency_id = client._identity.agency_id

    class _EmptyAgencyIdentity:
        element_id = "ecrf.test.example.com"
        agency_id = ""

    client._identity = _EmptyAgencyIdentity()  # type: ignore[assignment]

    with caplog.at_level(logging.WARNING, logger="i3_fe_core.logging.logging_client"):
        body = await client.emit(event)

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) >= 1
    assert "agencyId" in warnings[0].message.lower() or "mandatory" in warnings[0].message.lower()


@pytest.mark.asyncio
async def test_empty_agency_id_still_emits():
    """Even with empty agencyId, emit() MUST still return a body (not raise)."""
    client = _make_client()

    class _EmptyAgencyIdentity:
        element_id = "ecrf.test.example.com"
        agency_id = ""

    client._identity = _EmptyAgencyIdentity()  # type: ignore[assignment]
    body = await client.emit(LogEventPrologue(log_event_type="TestEvent"))
    assert "logEventType" in body


# ---------------------------------------------------------------------------
# emit() — no HTTP when logging_service_uri is None
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_http_post_when_no_uri():
    fake = _FakeHttpClient()
    client = _make_client(logging_service_uri=None, http_client=fake)  # type: ignore[arg-type]
    await client.emit(LogEventPrologue(log_event_type="TestEvent"))
    assert len(fake.posts) == 0


# ---------------------------------------------------------------------------
# emit() — HTTP POST to Logging Service
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_http_post_when_uri_configured():
    fake = _FakeHttpClient(status_code=201)
    client = _make_client(
        logging_service_uri="https://ls.example.com",
        http_client=fake,  # type: ignore[arg-type]
    )
    await client.emit(LogEventPrologue(log_event_type="TestEvent"))
    assert len(fake.posts) == 1


@pytest.mark.asyncio
async def test_http_post_url_contains_log_events_path():
    fake = _FakeHttpClient()
    client = _make_client(
        logging_service_uri="https://ls.example.com",
        http_client=fake,  # type: ignore[arg-type]
    )
    await client.emit(LogEventPrologue(log_event_type="TestEvent"))
    assert fake.posts[0]["url"].endswith("/LogEvents")


@pytest.mark.asyncio
async def test_http_post_content_is_valid_json():
    fake = _FakeHttpClient()
    client = _make_client(
        logging_service_uri="https://ls.example.com",
        http_client=fake,  # type: ignore[arg-type]
    )
    await client.emit(LogEventPrologue(log_event_type="TestEvent"))
    payload = json.loads(fake.posts[0]["content"])
    assert payload["logEventType"] == "TestEvent"


@pytest.mark.asyncio
async def test_http_post_content_type_json_without_signing():
    fake = _FakeHttpClient()
    client = _make_client(
        logging_service_uri="https://ls.example.com",
        http_client=fake,  # type: ignore[arg-type]
    )
    await client.emit(LogEventPrologue(log_event_type="TestEvent"))
    assert fake.posts[0]["headers"]["Content-Type"] == "application/json"


# ---------------------------------------------------------------------------
# JWS signing hook
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sign_payload_hook_called_when_provided():
    signed_calls: list[dict] = []

    def mock_signer(body: dict) -> bytes:
        signed_calls.append(body)
        return b"signed.payload.here"

    fake = _FakeHttpClient()
    client = _make_client(
        logging_service_uri="https://ls.example.com",
        http_client=fake,  # type: ignore[arg-type]
        sign_payload=mock_signer,
    )
    await client.emit(LogEventPrologue(log_event_type="TestEvent"))
    assert len(signed_calls) == 1
    assert signed_calls[0]["logEventType"] == "TestEvent"


@pytest.mark.asyncio
async def test_sign_payload_hook_content_type_is_jose():
    def mock_signer(body: dict) -> bytes:
        return b"signed.payload.here"

    fake = _FakeHttpClient()
    client = _make_client(
        logging_service_uri="https://ls.example.com",
        http_client=fake,  # type: ignore[arg-type]
        sign_payload=mock_signer,
    )
    await client.emit(LogEventPrologue(log_event_type="TestEvent"))
    assert fake.posts[0]["headers"]["Content-Type"] == "application/jose"


@pytest.mark.asyncio
async def test_sign_payload_hook_posts_signed_bytes():
    def mock_signer(body: dict) -> bytes:
        return b"compact.jws"

    fake = _FakeHttpClient()
    client = _make_client(
        logging_service_uri="https://ls.example.com",
        http_client=fake,  # type: ignore[arg-type]
        sign_payload=mock_signer,
    )
    await client.emit(LogEventPrologue(log_event_type="TestEvent"))
    assert fake.posts[0]["content"] == b"compact.jws"
