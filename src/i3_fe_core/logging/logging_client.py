"""LoggingClient — emit LogEvents to stdlib logging and the i3 Logging Service.

Covers: NENA-STA-010.3f-2021 §4.12.3.1 (LogEvent prologue population) and
§4.12.3.1.2 (Post Event — HTTP POST to the Logging Service).

Transport
---------
LogEvents are stored by the Logging Service as a JWS [§5.10].  When a
``logging_service_uri`` is configured, ``emit()`` POSTs the serialized
LogEvent to ``.../LogEvents``.

JWS SIGNING (§4.12.3.1, §5.10)
--------------------------------
Pass a ``JwsSigner`` instance's ``sign`` method as ``sign_payload`` to enable
EdDSA/Ed448 Flat JWS JSON signing::

    from i3_fe_core.logging.jws_signer import JwsSigner
    signer = JwsSigner(private_key=ed448_key, cert_chain=[leaf_cert, intermediate])
    client = LoggingClient(identity=identity, sign_payload=signer.sign)

When ``sign_payload`` is None, raw JSON is POSTed — acceptable when the
Logging Service policy allows unsigned events (``requiredAlgorithms`` contains
``"none"`` per §5.10).

mTLS caveat (§2.8, same as SIP notifier)
-----------------------------------------
Behind gunicorn + UvicornWorker, TLS client-cert enforcement is unreliable.
See notify/sip_notifier.py for the full note.
"""

from __future__ import annotations

import asyncio
import json
import logging as _stdlib_logging
from collections.abc import Callable
from typing import Any

import httpx

from i3_fe_core.config.identity import ElementIdentity
from i3_fe_core.logging.logevent import LogEventPrologue, prologue_to_dict
from i3_fe_core.time.timestamps import format_i3, now_i3

_log = _stdlib_logging.getLogger(__name__)


class LoggingClient:
    """Fills in infrastructure prologue fields and emits LogEvents.

    Usage::

        client = LoggingClient(
            identity=identity,
            logging_service_uri="https://ls.example.com",
        )
        event = LogEventPrologue(log_event_type="ElementStateChangeLogEvent")
        event.call_id = call_id
        body = await client.emit(event)

    The caller supplies only event-specific fields (logEventType, optional
    conditionals).  ``emit()`` stamps elementId, agencyId, and timestamp from
    the injected identity and the system clock.

    JWS signing
    -----------
    Pass a ``sign_payload`` callable to wrap the body in a JWS before posting.
    If omitted, the raw JSON is posted (acceptable when the Logging Service
    policy allows unsigned events — ``requiredAlgorithms`` contains "none").
    """

    def __init__(
        self,
        identity: ElementIdentity,
        logging_service_uri: str | None = None,
        http_client: httpx.AsyncClient | None = None,
        sign_payload: Callable[[dict[str, Any]], bytes] | None = None,
    ) -> None:
        """
        Args:
            identity:             Source of elementId and agencyId.
            logging_service_uri:  Base URI of the Logging Service.  When set,
                                  ``emit()`` POSTs to ``{uri}/LogEvents``.
                                  When None (default), HTTP is skipped.
            http_client:          Injected httpx.AsyncClient (tests / custom TLS).
                                  When None, a default client is created.
            sign_payload:         JWS HOOK — callable that takes the serialized
                                  body dict and returns the signed bytes to POST.
                                  When None, raw JSON is posted.
        """
        self._identity = identity
        self._logging_service_uri = logging_service_uri
        self._http_client = http_client or httpx.AsyncClient()
        self._sign_payload = sign_payload
        # Holds references to fire-and-forget POST tasks scheduled by
        # emit_nowait() so they are not garbage-collected mid-flight.
        self._bg_tasks: set[asyncio.Task[Any]] = set()

    def _stamp_serialize_log(self, event: LogEventPrologue) -> dict[str, Any]:
        """Populate infrastructure prologue fields, serialise, and emit to
        stdlib logging.  Shared by emit() and emit_nowait().

        Steps:
          1. Populate elementId, agencyId from the injected identity.
          2. Stamp timestamp from now_i3() (overrides any caller-set value).
          3. Warn (but still emit) when agencyId is empty — MANDATORY per
             §4.12.3.1.
          4. Serialise to a camelCase JSON dict.
          5. Emit via stdlib logging.

        Returns the serialised body dict.
        """
        event.element_id = self._identity.element_id
        event.agency_id = self._identity.agency_id
        event.timestamp = now_i3()

        if not event.agency_id:
            _log.warning(
                "LogEvent type=%r has empty agencyId — agencyId is MANDATORY "
                "per §4.12.3.1; event emitted but may be rejected by the "
                "Logging Service",
                event.log_event_type,
            )

        body = prologue_to_dict(event)
        _log.info("LogEvent: %s", json.dumps(body, ensure_ascii=False))
        return body

    async def emit(self, event: LogEventPrologue) -> dict[str, Any]:
        """Stamp infrastructure fields, serialise, emit to stdlib logging, and
        POST to the Logging Service when a logging_service_uri is configured.

        Returns the serialised body dict (useful for callers / tests).
        """
        body = self._stamp_serialize_log(event)
        if self._logging_service_uri:
            await self._post(body)
        return body

    def emit_nowait(self, event: LogEventPrologue) -> dict[str, Any]:
        """Synchronous, non-blocking counterpart to emit().

        For emission sites that are themselves synchronous and must not block
        (ElementState/ServiceState dispatch, SUBSCRIBE handling, DR resolution
        receipt).  Stamps, serialises, and emits to stdlib logging exactly as
        emit() does — always, synchronously.

        The HTTP POST to the Logging Service is best-effort:
          - When an asyncio event loop is running, the POST is scheduled as a
            background task (fire-and-forget); a reference is held until the
            task completes so it is not garbage-collected mid-flight.
          - When no loop is running (synchronous / test context), the POST is
            skipped with a debug log — the event is still emitted to stdlib
            logging.  This mirrors the "no running loop → degrade gracefully"
            fallback used by the state notifiers and SipNotifier.

        Returns the serialised body dict.
        """
        body = self._stamp_serialize_log(event)

        if self._logging_service_uri:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                _log.debug(
                    "emit_nowait: no running event loop — POST of LogEvent "
                    "type=%r skipped (event still logged to stdlib logging)",
                    event.log_event_type,
                )
            else:
                task = loop.create_task(self._post(body))
                self._bg_tasks.add(task)
                task.add_done_callback(self._bg_tasks.discard)

        return body

    # ------------------------------------------------------------------
    # Internal HTTP transport
    # ------------------------------------------------------------------

    async def _post(self, body: dict[str, Any]) -> httpx.Response:
        """POST *body* to the Logging Service.

        JWS HOOK: when ``self._sign_payload`` is set, the signed bytes are
        posted with Content-Type ``application/jose``; otherwise the raw
        JSON is posted with Content-Type ``application/json``.
        """
        url = f"{self._logging_service_uri.rstrip('/')}/LogEvents"

        if self._sign_payload is not None:
            # JWS path — signer produces Flat JWS JSON (§5.10).
            payload = self._sign_payload(body)
            content_type = "application/jose"
        else:
            payload = json.dumps(body, ensure_ascii=False).encode()
            content_type = "application/json"

        try:
            response = await self._http_client.post(
                url,
                content=payload,
                headers={"Content-Type": content_type},
            )
            if response.status_code not in {200, 201}:
                _log.warning(
                    "Logging Service returned %d for LogEvent type=%r",
                    response.status_code,
                    body.get("logEventType"),
                )
            return response
        except Exception:
            _log.exception(
                "Failed to POST LogEvent type=%r to %s",
                body.get("logEventType"),
                url,
            )
            raise
