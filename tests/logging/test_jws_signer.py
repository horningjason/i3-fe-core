"""Tests for logging/jws_signer.py — JWS signing and verification (§4.12.3.1, §5.10).

All tests are pure unit tests: no network, no real certificate files.
``make_test_credential()`` produces an in-memory Ed448 key pair and
self-signed certificate.
"""

from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from i3_fe_core.config.identity import ElementIdentity
from i3_fe_core.logging.jws_signer import (
    DISCREPANCY_PROBLEMS,
    CertDelivery,
    JwsSigner,
    LogSignDiscrepancyReport,
    _b64url_decode,
    _b64url_encode,
    verify_jws,
)
from i3_fe_core.logging.logging_client import LoggingClient
from i3_fe_core.logging.logevent import LogEventPrologue
from i3_fe_core.testing import make_test_credential


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def credential():
    """Generate once per module — Ed448 key generation is slow-ish."""
    return make_test_credential()


@pytest.fixture(scope="module")
def signer_by_value(credential):
    key, cert = credential
    return JwsSigner(private_key=key, cert_chain=[cert])


@pytest.fixture(scope="module")
def signer_by_ref(credential):
    key, cert = credential
    return JwsSigner(
        private_key=key,
        cert_chain=[cert],
        cert_delivery=CertDelivery.BY_REFERENCE,
        cert_url="https://pca.esinet.example/certs/element.p7b",
    )


_SAMPLE_PAYLOAD = {"logEventType": "AccessLogEvent", "elementId": "lvf.test.example"}


# ---------------------------------------------------------------------------
# make_test_credential
# ---------------------------------------------------------------------------

def test_make_test_credential_returns_key_and_cert():
    key, cert = make_test_credential()
    assert key is not None
    assert cert is not None


def test_make_test_credential_produces_ed448_key():
    from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
    key, _ = make_test_credential()
    assert isinstance(key, Ed448PrivateKey)


def test_make_test_credential_cert_public_key_matches_private_key():
    key, cert = make_test_credential()
    priv_pub = key.public_key()
    cert_pub = cert.public_key()
    # Both must serialise to the same raw public bytes
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    assert priv_pub.public_bytes(Encoding.Raw, PublicFormat.Raw) == \
           cert_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


# ---------------------------------------------------------------------------
# JwsSigner construction
# ---------------------------------------------------------------------------

def test_signer_requires_non_empty_cert_chain(credential):
    key, _ = credential
    with pytest.raises(ValueError, match="cert_chain"):
        JwsSigner(private_key=key, cert_chain=[])


def test_signer_by_reference_requires_cert_url(credential):
    key, cert = credential
    with pytest.raises(ValueError, match="cert_url"):
        JwsSigner(
            private_key=key,
            cert_chain=[cert],
            cert_delivery=CertDelivery.BY_REFERENCE,
        )


def test_signer_repr_excludes_private_key(signer_by_value):
    """NG-SEC §6.23.7: private keys SHALL be protected from unauthorized
    disclosure — repr() must not include the private key field."""
    assert "private_key" not in repr(signer_by_value)


# ---------------------------------------------------------------------------
# JwsSigner.sign — Flat JWS JSON structure
# ---------------------------------------------------------------------------

def test_sign_produces_bytes(signer_by_value):
    result = signer_by_value.sign(_SAMPLE_PAYLOAD)
    assert isinstance(result, bytes)


def test_sign_produces_valid_json(signer_by_value):
    result = signer_by_value.sign(_SAMPLE_PAYLOAD)
    parsed = json.loads(result)
    assert isinstance(parsed, dict)


def test_sign_flat_jws_has_payload_protected_signature(signer_by_value):
    """§5.10: Flat JWS JSON MUST have payload, protected, signature fields."""
    parsed = json.loads(signer_by_value.sign(_SAMPLE_PAYLOAD))
    assert "payload" in parsed
    assert "protected" in parsed
    assert "signature" in parsed


def test_sign_no_extra_top_level_fields(signer_by_value):
    """Flat JWS JSON (not General) must NOT have a signatures array."""
    parsed = json.loads(signer_by_value.sign(_SAMPLE_PAYLOAD))
    assert "signatures" not in parsed   # would indicate General serialisation


def test_sign_alg_is_eddsa(signer_by_value):
    """§5.10: algorithm MUST be EdDSA."""
    parsed = json.loads(signer_by_value.sign(_SAMPLE_PAYLOAD))
    header = json.loads(_b64url_decode(parsed["protected"]))
    assert header["alg"] == "EdDSA"


def test_sign_payload_encodes_original_dict(signer_by_value):
    parsed = json.loads(signer_by_value.sign(_SAMPLE_PAYLOAD))
    decoded = json.loads(_b64url_decode(parsed["payload"]))
    assert decoded == _SAMPLE_PAYLOAD


# ---------------------------------------------------------------------------
# By-value certificate (x5c)
# ---------------------------------------------------------------------------

def test_sign_by_value_has_x5c(signer_by_value):
    """BY_VALUE mode MUST embed x5c in the Protected Header."""
    parsed = json.loads(signer_by_value.sign(_SAMPLE_PAYLOAD))
    header = json.loads(_b64url_decode(parsed["protected"]))
    assert "x5c" in header


def test_sign_by_value_no_x5u(signer_by_value):
    parsed = json.loads(signer_by_value.sign(_SAMPLE_PAYLOAD))
    header = json.loads(_b64url_decode(parsed["protected"]))
    assert "x5u" not in header


def test_sign_by_value_x5c_is_base64_der(signer_by_value, credential):
    """§5.10: x5c values are base64-encoded DER (not base64url)."""
    _, cert = credential
    parsed = json.loads(signer_by_value.sign(_SAMPLE_PAYLOAD))
    header = json.loads(_b64url_decode(parsed["protected"]))
    # First element is the leaf cert; must round-trip to the same DER
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509 import load_der_x509_certificate
    leaf_der = base64.b64decode(header["x5c"][0])
    reloaded = load_der_x509_certificate(leaf_der)
    assert reloaded.public_bytes(Encoding.DER) == cert.public_bytes(Encoding.DER)


def test_sign_cert_chain_all_certs_included(credential):
    """When cert_chain has multiple certs, all MUST appear in x5c."""
    key, cert = credential
    _, intermediate = make_test_credential()  # second cert as stand-in for intermediate
    signer = JwsSigner(private_key=key, cert_chain=[cert, intermediate])
    parsed = json.loads(signer.sign(_SAMPLE_PAYLOAD))
    header = json.loads(_b64url_decode(parsed["protected"]))
    assert len(header["x5c"]) == 2


# ---------------------------------------------------------------------------
# By-reference certificate (x5u + x5t#S256)
# ---------------------------------------------------------------------------

def test_sign_by_ref_has_x5u_and_thumbprint(signer_by_ref):
    """BY_REFERENCE mode MUST include x5u and x5t#S256."""
    parsed = json.loads(signer_by_ref.sign(_SAMPLE_PAYLOAD))
    header = json.loads(_b64url_decode(parsed["protected"]))
    assert "x5u" in header
    assert "x5t#S256" in header


def test_sign_by_ref_no_x5c(signer_by_ref):
    parsed = json.loads(signer_by_ref.sign(_SAMPLE_PAYLOAD))
    header = json.loads(_b64url_decode(parsed["protected"]))
    assert "x5c" not in header


def test_sign_by_ref_x5u_is_correct(signer_by_ref):
    parsed = json.loads(signer_by_ref.sign(_SAMPLE_PAYLOAD))
    header = json.loads(_b64url_decode(parsed["protected"]))
    assert header["x5u"] == "https://pca.esinet.example/certs/element.p7b"


def test_sign_by_ref_thumbprint_matches_leaf_cert(signer_by_ref, credential):
    """§5.10: x5t#S256 MUST be the SHA-256 of the leaf cert's DER encoding."""
    import hashlib
    from cryptography.hazmat.primitives.serialization import Encoding
    _, cert = credential
    parsed = json.loads(signer_by_ref.sign(_SAMPLE_PAYLOAD))
    header = json.loads(_b64url_decode(parsed["protected"]))
    expected = _b64url_encode(hashlib.sha256(cert.public_bytes(Encoding.DER)).digest())
    assert header["x5t#S256"] == expected


# ---------------------------------------------------------------------------
# verify_jws — success cases
# ---------------------------------------------------------------------------

def test_verify_jws_by_value_succeeds(signer_by_value):
    jws = signer_by_value.sign(_SAMPLE_PAYLOAD)
    payload, report = verify_jws(jws)
    assert report is None
    assert payload == _SAMPLE_PAYLOAD


def test_verify_jws_returns_correct_payload(signer_by_value):
    data = {"logEventType": "CallStartLogEvent", "callId": "urn:uid:123"}
    payload, report = verify_jws(signer_by_value.sign(data))
    assert report is None
    assert payload["callId"] == "urn:uid:123"


def test_verify_jws_by_ref_with_trusted_cert(signer_by_ref, credential):
    _, cert = credential
    jws = signer_by_ref.sign(_SAMPLE_PAYLOAD)
    payload, report = verify_jws(jws, trusted_certs=[cert])
    assert report is None
    assert payload == _SAMPLE_PAYLOAD


def _make_unsigned_jws() -> bytes:
    payload_b64 = _b64url_encode(json.dumps(_SAMPLE_PAYLOAD, separators=(",", ":")).encode())
    header_b64 = _b64url_encode(json.dumps({"alg": "none"}, separators=(",", ":")).encode())
    # unsigned: signature is empty string per RFC 7515 §A.5
    return json.dumps(
        {"payload": payload_b64, "protected": header_b64, "signature": ""},
        separators=(",", ":"),
    ).encode()


def test_verify_unsigned_jws_passes_when_policy_allows():
    """§5.10: alg=none (unsigned) is accepted when policy explicitly allows it."""
    payload, report = verify_jws(_make_unsigned_jws(), allow_unsigned=True)
    assert report is None
    assert payload == _SAMPLE_PAYLOAD


def test_verify_unsigned_jws_rejected_by_default():
    """Signature-stripping defence: alg=none MUST be rejected unless opted in."""
    payload, report = verify_jws(_make_unsigned_jws())
    assert report is not None
    assert report.problem == "BadAlgorithm"


def test_verify_signed_jws_downgraded_to_none_is_rejected(signer_by_value):
    """An attacker stripping the signature and setting alg=none must not pass."""
    jws_dict = json.loads(signer_by_value.sign(_SAMPLE_PAYLOAD))
    jws_dict["protected"] = _b64url_encode(
        json.dumps({"alg": "none"}, separators=(",", ":")).encode()
    )
    jws_dict["signature"] = ""
    _, report = verify_jws(json.dumps(jws_dict, separators=(",", ":")).encode())
    assert report is not None
    assert report.problem == "BadAlgorithm"


# ---------------------------------------------------------------------------
# verify_jws — failure cases → LogSignDiscrepancyReport
# ---------------------------------------------------------------------------

def test_verify_jws_tampered_payload_returns_bad_signature(signer_by_value):
    """§3.7.22: BadSignature when payload is altered after signing."""
    jws_dict = json.loads(signer_by_value.sign(_SAMPLE_PAYLOAD))
    jws_dict["payload"] = _b64url_encode(b'{"logEventType":"Tampered"}')
    tampered = json.dumps(jws_dict, separators=(",", ":")).encode()

    payload, report = verify_jws(tampered)
    assert report is not None
    assert report.problem == "BadSignature"


def test_verify_jws_tampered_protected_header_returns_bad_signature(signer_by_value, credential):
    """Altering the Protected Header invalidates the signing input."""
    key, cert = credential
    from cryptography.hazmat.primitives.serialization import Encoding
    jws_dict = json.loads(signer_by_value.sign(_SAMPLE_PAYLOAD))
    # Re-encode the same header with an extra field → different base64 → signing input changes
    header = json.loads(_b64url_decode(jws_dict["protected"]))
    header["extra"] = "injected"
    jws_dict["protected"] = _b64url_encode(
        json.dumps(header, separators=(",", ":")).encode()
    )
    tampered = json.dumps(jws_dict, separators=(",", ":")).encode()

    payload, report = verify_jws(tampered)
    assert report is not None
    assert report.problem == "BadSignature"


def test_verify_jws_wrong_algorithm_returns_bad_algorithm():
    """§3.7.22: BadAlgorithm when alg is not EdDSA or none."""
    import json as _json
    payload_b64 = _b64url_encode(_json.dumps(_SAMPLE_PAYLOAD, separators=(",", ":")).encode())
    header_b64 = _b64url_encode(_json.dumps({"alg": "RS256"}, separators=(",", ":")).encode())
    jws = _json.dumps(
        {"payload": payload_b64, "protected": header_b64, "signature": "fake"},
        separators=(",", ":"),
    ).encode()
    _, report = verify_jws(jws)
    assert report is not None
    assert report.problem == "BadAlgorithm"


def test_verify_jws_no_cert_fields_returns_no_cert():
    """§3.7.22: NoCert when neither x5c nor x5u present."""
    import json as _json
    payload_b64 = _b64url_encode(_json.dumps(_SAMPLE_PAYLOAD, separators=(",", ":")).encode())
    header_b64 = _b64url_encode(_json.dumps({"alg": "EdDSA"}, separators=(",", ":")).encode())
    jws = _json.dumps(
        {"payload": payload_b64, "protected": header_b64, "signature": "fake"},
        separators=(",", ":"),
    ).encode()
    _, report = verify_jws(jws)
    assert report is not None
    assert report.problem == "NoCert"


def test_verify_jws_by_ref_without_trusted_certs_returns_bad_url(signer_by_ref):
    """§3.7.22: BadURL when x5u present but no cert supplied by caller."""
    jws = signer_by_ref.sign(_SAMPLE_PAYLOAD)
    _, report = verify_jws(jws)
    assert report is not None
    assert report.problem == "BadURL"
    assert report.result is not None  # BadURL requires result field


def test_verify_jws_bad_thumbprint_returns_bad_thumb(signer_by_ref):
    """§3.7.22: BadThumb when x5t#S256 does not match supplied cert."""
    _, wrong_cert = make_test_credential()   # different cert → different thumbprint
    jws = signer_by_ref.sign(_SAMPLE_PAYLOAD)
    _, report = verify_jws(jws, trusted_certs=[wrong_cert])
    assert report is not None
    assert report.problem == "BadThumb"
    assert report.thumb_calc is not None   # calculated thumbprint REQUIRED per §3.7.22


def test_verify_jws_bad_x5c_cert_returns_bad_cert_x5c():
    """§3.7.22: BadCertX5c for invalid base64 or corrupt DER in x5c."""
    import json as _json
    payload_b64 = _b64url_encode(_json.dumps(_SAMPLE_PAYLOAD, separators=(",", ":")).encode())
    header = {"alg": "EdDSA", "x5c": [base64.b64encode(b"not a cert").decode()]}
    header_b64 = _b64url_encode(_json.dumps(header, separators=(",", ":")).encode())
    jws = _json.dumps(
        {"payload": payload_b64, "protected": header_b64, "signature": "fake"},
        separators=(",", ":"),
    ).encode()
    _, report = verify_jws(jws)
    assert report is not None
    assert report.problem == "BadCertX5c"


def test_verify_jws_by_ref_missing_thumbprint_returns_bad_thumb():
    """§5.10: x5u without x5t#S256 → BadThumb (can't verify cert integrity)."""
    import json as _json
    payload_b64 = _b64url_encode(_json.dumps(_SAMPLE_PAYLOAD, separators=(",", ":")).encode())
    header = {"alg": "EdDSA", "x5u": "https://pca.example/cert"}  # no x5t#S256
    header_b64 = _b64url_encode(_json.dumps(header, separators=(",", ":")).encode())
    jws = _json.dumps(
        {"payload": payload_b64, "protected": header_b64, "signature": "fake"},
        separators=(",", ":"),
    ).encode()
    _, report = verify_jws(jws)
    assert report is not None
    assert report.problem == "BadThumb"


# ---------------------------------------------------------------------------
# verify_jws — trust anchoring and hostile input
# ---------------------------------------------------------------------------

def test_verify_jws_x5c_forged_cert_rejected_with_trust_anchors(credential):
    """A JWS signed by an attacker's own key/cert must fail when anchors are given."""
    _, real_cert = credential
    forged_key, forged_cert = make_test_credential()   # attacker credential
    forged = JwsSigner(private_key=forged_key, cert_chain=[forged_cert])
    jws = forged.sign(_SAMPLE_PAYLOAD)

    _, report = verify_jws(jws, trusted_certs=[real_cert])
    assert report is not None
    assert report.problem == "BadCertX5c"


def test_verify_jws_x5c_anchored_to_trusted_cert_succeeds(signer_by_value, credential):
    """The legitimate signer's cert passes when it is a supplied trust anchor."""
    _, cert = credential
    jws = signer_by_value.sign(_SAMPLE_PAYLOAD)
    payload, report = verify_jws(jws, trusted_certs=[cert])
    assert report is None
    assert payload == _SAMPLE_PAYLOAD


def test_verify_jws_non_json_input_returns_report():
    """Hostile/garbage input must yield a report, not an exception."""
    payload, report = verify_jws(b"not json at all")
    assert payload == {}
    assert report is not None
    assert report.problem == "OtherLogSignature"


def test_verify_jws_non_object_json_returns_report():
    """A JSON array/scalar is not a Flat JWS JSON object."""
    payload, report = verify_jws(b'["payload", "protected", "signature"]')
    assert payload == {}
    assert report is not None
    assert report.problem == "OtherLogSignature"


def test_verify_jws_unknown_crit_header_rejected(credential):
    """RFC 7515 §4.1.11: unsupported critical header params must reject."""
    from cryptography.hazmat.primitives.serialization import Encoding
    key, cert = credential
    payload_b64 = _b64url_encode(json.dumps(_SAMPLE_PAYLOAD, separators=(",", ":")).encode())
    header = {
        "alg": "EdDSA",
        "crit": ["exp"],
        "x5c": [base64.b64encode(cert.public_bytes(Encoding.DER)).decode()],
    }
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    sig = key.sign((header_b64 + "." + payload_b64).encode())
    jws = json.dumps(
        {"payload": payload_b64, "protected": header_b64, "signature": _b64url_encode(sig)},
        separators=(",", ":"),
    ).encode()
    _, report = verify_jws(jws)
    assert report is not None
    assert report.problem == "OtherLogSignature"


# ---------------------------------------------------------------------------
# LogSignDiscrepancyReport
# ---------------------------------------------------------------------------

def test_discrepancy_report_to_dict_mandatory_fields():
    r = LogSignDiscrepancyReport(problem="BadSignature", log_event_id="evt-001")
    d = r.to_dict()
    assert d["problem"] == "BadSignature"
    assert d["logEventId"] == "evt-001"
    assert "result" not in d
    assert "thumbCalc" not in d


def test_discrepancy_report_to_dict_with_result():
    r = LogSignDiscrepancyReport(
        problem="BadURL",
        log_event_id="evt-002",
        result="404 Not Found",
    )
    d = r.to_dict()
    assert d["result"] == "404 Not Found"


def test_discrepancy_report_to_dict_with_thumb_calc():
    r = LogSignDiscrepancyReport(
        problem="BadThumb",
        log_event_id="evt-003",
        thumb_calc="abc123",
    )
    d = r.to_dict()
    assert d["thumbCalc"] == "abc123"


def test_discrepancy_report_invalid_problem_raises():
    with pytest.raises(ValueError, match="problem"):
        LogSignDiscrepancyReport(problem="NotAValidToken", log_event_id="x")


def test_discrepancy_problems_set_covers_all_standard_tokens():
    """§3.7.22: All 8 problem tokens must be present in DISCREPANCY_PROBLEMS."""
    expected = {
        "BadAlgorithm", "NoCert", "BadURL", "BadThumb",
        "BadCertX5c", "BadCertX5u", "BadSignature", "OtherLogSignature",
    }
    assert expected == DISCREPANCY_PROBLEMS


# ---------------------------------------------------------------------------
# Integration with LoggingClient
# ---------------------------------------------------------------------------

def _make_identity() -> ElementIdentity:
    return ElementIdentity(
        element_id="lvf.psap.allegheny.pa.us",
        agency_id="psap.allegheny.pa.us",
        agent_id="dispatcher1",
        service_id="lvf.psap.allegheny.pa.us",
        service_name="LVF",
    )


@pytest.mark.asyncio
async def test_logging_client_posts_application_jose_when_signer_wired(credential):
    """LoggingClient MUST use Content-Type: application/jose when sign_payload is set."""
    key, cert = credential
    signer = JwsSigner(private_key=key, cert_chain=[cert])

    captured: list[dict] = []

    async def mock_post(url, *, content, headers, **_):
        captured.append({"url": url, "content": content, "headers": headers})
        return httpx.Response(201)

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.post = mock_post

    client = LoggingClient(
        identity=_make_identity(),
        logging_service_uri="https://ls.example.com",
        http_client=mock_client,
        sign_payload=signer.sign,
    )
    await client.emit(LogEventPrologue(log_event_type="AccessLogEvent"))

    assert captured, "expected at least one POST"
    assert captured[0]["headers"]["Content-Type"] == "application/jose"


@pytest.mark.asyncio
async def test_logging_client_posted_body_is_valid_flat_jws(credential):
    """The posted content must be valid Flat JWS JSON."""
    key, cert = credential
    signer = JwsSigner(private_key=key, cert_chain=[cert])

    captured: list[bytes] = []

    async def mock_post(url, *, content, headers, **_):
        captured.append(content)
        return httpx.Response(201)

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.post = mock_post

    client = LoggingClient(
        identity=_make_identity(),
        logging_service_uri="https://ls.example.com",
        http_client=mock_client,
        sign_payload=signer.sign,
    )
    await client.emit(LogEventPrologue(log_event_type="AccessLogEvent"))

    jws_bytes = captured[0]
    parsed = json.loads(jws_bytes)
    assert "payload" in parsed
    assert "protected" in parsed
    assert "signature" in parsed


@pytest.mark.asyncio
async def test_logging_client_posted_jws_verifies_correctly(credential):
    """The posted JWS must verify without a discrepancy report."""
    key, cert = credential
    signer = JwsSigner(private_key=key, cert_chain=[cert])

    captured: list[bytes] = []

    async def mock_post(url, *, content, headers, **_):
        captured.append(content)
        return httpx.Response(201)

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.post = mock_post

    client = LoggingClient(
        identity=_make_identity(),
        logging_service_uri="https://ls.example.com",
        http_client=mock_client,
        sign_payload=signer.sign,
    )
    await client.emit(LogEventPrologue(log_event_type="AccessLogEvent"))

    payload_dict, report = verify_jws(captured[0])
    assert report is None
    assert payload_dict.get("logEventType") == "AccessLogEvent"
    assert payload_dict.get("elementId") == "lvf.psap.allegheny.pa.us"


@pytest.mark.asyncio
async def test_logging_client_jws_payload_contains_all_mandatory_prologue_fields(credential):
    """The JWS payload MUST contain all §4.12.3.1 mandatory prologue fields."""
    key, cert = credential
    signer = JwsSigner(private_key=key, cert_chain=[cert])

    captured: list[bytes] = []

    async def mock_post(url, *, content, headers, **_):
        captured.append(content)
        return httpx.Response(201)

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.post = mock_post

    client = LoggingClient(
        identity=_make_identity(),
        logging_service_uri="https://ls.example.com",
        http_client=mock_client,
        sign_payload=signer.sign,
    )
    await client.emit(LogEventPrologue(log_event_type="AccessLogEvent"))

    payload_dict, _ = verify_jws(captured[0])
    for field in ("logEventType", "timestamp", "elementId", "agencyId"):
        assert field in payload_dict, f"mandatory field {field!r} missing from JWS payload"
