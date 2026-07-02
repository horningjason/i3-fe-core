"""JWS signing and verification for i3 LogEvents (§4.12.3.1, §5.10).

Standard requirements (§5.10)
------------------------------
* JWS MUST use **Flat JSON Serialization** (not Compact, not General).
* The algorithm MUST be ``"EdDSA"`` (Edwards-curve DSA with Curve448 / Ed448).
* Unsigned events are indicated by ``"alg": "none"`` — acceptable when the
  Logging Service policy allows it (``requiredAlgorithms`` contains ``"none"``).
* The Protected Header MUST specify the signing entity's X.509 certificate
  **and all intermediate certs up to a PCA-traceable root**.  Two delivery modes:

    By value:     ``x5c`` — array of base64-encoded DER certificates (leaf first).
    By reference: ``x5u`` (URL stable for ≥ 10 years) + ``x5t#S256`` (SHA-256
                  thumbprint of the leaf cert, base64url-encoded).

Signer usage
------------
::

    from i3_fe_core.logging.jws_signer import JwsSigner, CertDelivery
    from i3_fe_core.logging.logging_client import LoggingClient

    signer = JwsSigner(
        private_key=my_ed448_key,
        cert_chain=[leaf_cert, intermediate_cert],
    )
    client = LoggingClient(
        identity=identity,
        logging_service_uri="https://ls.example.com",
        sign_payload=signer.sign,   # JWS hook
    )

Verify usage
------------
::

    from i3_fe_core.logging.jws_signer import verify_jws

    payload, report = verify_jws(jws_bytes)
    if report is not None:
        # report is a LogSignDiscrepancyReport — submit it per §3.7.22
        ...

For production use, PCA-traceable certificates must be used.  See
``i3_fe_core.testing.make_test_credential()`` for a test-only key/cert
generator (deliberately kept out of this module — see that module's
docstring for why).
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import logging
from dataclasses import dataclass, field
from enum import Enum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.x509 import Certificate, load_der_x509_certificate

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Base64-url helpers (RFC 4648 §5, no padding)
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + ("=" * (0 if pad == 4 else pad)))


# ---------------------------------------------------------------------------
# Certificate delivery mode
# ---------------------------------------------------------------------------

class CertDelivery(str, Enum):
    """How the signing certificate is included in the JWS Protected Header.

    BY_VALUE:     ``x5c`` — base64-encoded DER cert(s) inline.  Larger payloads
                  but no extra round-trips for verifiers.
    BY_REFERENCE: ``x5u`` + ``x5t#S256`` — URL pointer + SHA-256 thumbprint.
                  Smaller payloads; verifier must fetch the cert chain from the
                  URL, which MUST remain resolvable for ≥ 10 years (§5.10).
    """
    BY_VALUE = "by_value"
    BY_REFERENCE = "by_reference"


# ---------------------------------------------------------------------------
# Discrepancy Report (§3.7.22)
# ---------------------------------------------------------------------------

#: All allowed ``problem`` token values (§3.7.22).
DISCREPANCY_PROBLEMS: frozenset[str] = frozenset({
    "BadAlgorithm",    # alg not EdDSA
    "NoCert",          # neither x5u nor x5c present
    "BadURL",          # x5u cannot be resolved
    "BadThumb",        # x5t#S256 missing or does not match resolved cert
    "BadCertX5c",      # invalid cert in x5c field
    "BadCertX5u",      # invalid cert obtained via x5u
    "BadSignature",    # signature does not verify
    "OtherLogSignature",
})


@dataclass
class LogSignDiscrepancyReport:
    """§3.7.22 Log Signature/Certificate Discrepancy Report.

    When ``verify_jws()`` detects a problem it returns one of these.  The
    caller (e.g. a Logging Service or periodic verifier) is responsible for
    submitting it to the logging entity that generated the problematic event.

    Fields:
        problem:       One of ``DISCREPANCY_PROBLEMS``.
        log_event_id:  The ``logEventId`` of the LogEvent that failed (MANDATORY).
        result:        REQUIRED when ``problem == "BadURL"`` — the HTTP response
                       or error message received when resolving ``x5u``.
        thumb_calc:    REQUIRED when ``problem == "BadThumb"`` — the thumbprint
                       calculated from the certificate actually obtained.
    """
    problem: str
    log_event_id: str
    result: str | None = None
    thumb_calc: str | None = None

    def __post_init__(self) -> None:
        if self.problem not in DISCREPANCY_PROBLEMS:
            raise ValueError(
                f"problem {self.problem!r} is not in §3.7.22 token set; "
                f"allowed: {sorted(DISCREPANCY_PROBLEMS)}"
            )

    def to_dict(self) -> dict:
        """Serialise to a dict suitable for JSON transmission."""
        d: dict = {
            "problem": self.problem,
            "logEventId": self.log_event_id,
        }
        if self.result is not None:
            d["result"] = self.result
        if self.thumb_calc is not None:
            d["thumbCalc"] = self.thumb_calc
        return d


# ---------------------------------------------------------------------------
# JWS Signer
# ---------------------------------------------------------------------------

@dataclass
class JwsSigner:
    """Signs LogEvent dicts as Flat JWS JSON per §4.12.3.1 / §5.10.

    The :meth:`sign` method satisfies the ``sign_payload: Callable[[dict], bytes]``
    interface of :class:`~i3_fe_core.logging.logging_client.LoggingClient`, so it
    can be passed directly::

        signer = JwsSigner(private_key=key, cert_chain=[leaf, intermediate])
        client = LoggingClient(identity=identity, sign_payload=signer.sign)

    Args:
        private_key:    Ed448 private key (Curve448, algorithm "EdDSA").  MUST be
                        the private half of the certificate in ``cert_chain[0]``.
                        Excluded from repr() (NG-SEC §6.23.7: private keys SHALL
                        be protected from unauthorized disclosure) — defense in
                        depth against accidental exposure via logging or
                        tracebacks that print local/field values.
        cert_chain:     Certificate chain, leaf first.  MUST be PCA-traceable in
                        production.  All certs are included in the JWS header
                        (by-value) or implied by the ``x5u`` URL (by-reference).
        cert_delivery:  How the cert is conveyed.  Defaults to BY_VALUE.
        cert_url:       REQUIRED when ``cert_delivery == BY_REFERENCE``.  URL at
                        which the cert chain is permanently resolvable (§5.10).
    """
    private_key: Ed448PrivateKey = field(repr=False)
    cert_chain: list[Certificate]
    cert_delivery: CertDelivery = CertDelivery.BY_VALUE
    cert_url: str | None = None

    def __post_init__(self) -> None:
        if not self.cert_chain:
            raise ValueError("cert_chain must contain at least the leaf certificate")
        if self.cert_delivery == CertDelivery.BY_REFERENCE and not self.cert_url:
            raise ValueError("cert_url is required when cert_delivery == BY_REFERENCE")

    def sign(self, payload: dict) -> bytes:
        """Produce a Flat JWS JSON representation of *payload*.

        The returned bytes are valid JSON with the structure::

            {
                "payload":   "<BASE64URL(payload-json)>",
                "protected": "<BASE64URL(protected-header-json)>",
                "signature": "<BASE64URL(Ed448-signature)>"
            }

        The Protected Header contains ``"alg": "EdDSA"`` plus the certificate
        in the format determined by :attr:`cert_delivery`.

        Args:
            payload: The LogEvent body dict (output of ``prologue_to_dict()``).

        Returns:
            Flat JWS JSON as bytes — pass directly as the ``content`` body of
            an HTTP POST with ``Content-Type: application/jose``.
        """
        payload_b64 = _b64url_encode(
            json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
        )
        protected = self._build_protected_header()
        protected_b64 = _b64url_encode(
            json.dumps(protected, separators=(",", ":")).encode()
        )
        signing_input = (protected_b64 + "." + payload_b64).encode()
        signature = self.private_key.sign(signing_input)

        return json.dumps(
            {
                "payload": payload_b64,
                "protected": protected_b64,
                "signature": _b64url_encode(signature),
            },
            separators=(",", ":"),
        ).encode()

    def _build_protected_header(self) -> dict:
        header: dict = {"alg": "EdDSA"}
        if self.cert_delivery == CertDelivery.BY_VALUE:
            header["x5c"] = [
                base64.b64encode(
                    cert.public_bytes(serialization.Encoding.DER)
                ).decode()
                for cert in self.cert_chain
            ]
        else:
            leaf_der = self.cert_chain[0].public_bytes(serialization.Encoding.DER)
            thumbprint = _b64url_encode(hashlib.sha256(leaf_der).digest())
            header["x5u"] = self.cert_url
            header["x5t#S256"] = thumbprint
        return header


# ---------------------------------------------------------------------------
# JWS Verifier
# ---------------------------------------------------------------------------

def _cert_validity_ok(cert: Certificate) -> bool:
    """True when *cert* is within its notBefore/notAfter validity window."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def _chain_is_anchored(
    chain: list[Certificate], trusted: list[Certificate]
) -> bool:
    """True when ``chain[0]`` is, or chains up to, a certificate in *trusted*.

    Walks issuer signatures from the leaf through the supplied intermediates
    until a cert that either byte-matches a trusted cert or is directly issued
    by one.  Signature checks use ``Certificate.verify_directly_issued_by``.
    """
    trusted_ders = {t.public_bytes(serialization.Encoding.DER) for t in trusted}
    current = chain[0]
    remaining = list(chain[1:])
    # Bounded walk: at most one step per supplied cert.
    for _ in range(len(chain) + 1):
        if current.public_bytes(serialization.Encoding.DER) in trusted_ders:
            return True
        for anchor in trusted:
            try:
                current.verify_directly_issued_by(anchor)
                return True
            except Exception:
                continue
        issuer = None
        for candidate in remaining:
            try:
                current.verify_directly_issued_by(candidate)
                issuer = candidate
                break
            except Exception:
                continue
        if issuer is None:
            return False
        remaining.remove(issuer)
        current = issuer
    return False


def verify_jws(
    jws_bytes: bytes,
    *,
    trusted_certs: list[Certificate] | None = None,
    log_event_id: str = "",
    allow_unsigned: bool = False,
) -> tuple[dict, LogSignDiscrepancyReport | None]:
    """Verify a Flat JWS JSON LogEvent and return the payload and any discrepancy.

    Implements the verification side of §4.12.3.1 / §5.10.  Suitable for use
    in a periodic signature-validity check or inline Logging Service validation.

    Signed (``alg != "none"``) events are verified against the certificate
    embedded in or referenced from the JWS Protected Header:

    * ``x5c`` present → leaf cert decoded from the inline DER value.  When
      *trusted_certs* is supplied, the leaf MUST be one of (or chain up to)
      those certs; otherwise the signature is only checked for
      self-consistency against the sender-supplied cert, which does NOT
      authenticate the signer (a warning is logged).
    * ``x5u`` present → thumbprint is checked against *trusted_certs[0]* (caller
      must supply the cert obtained by fetching the URL; network fetch is out of
      scope for this helper).  A ``BadURL`` report is returned when no cert is
      provided.

    Args:
        jws_bytes:     Raw bytes of a Flat JWS JSON object.
        trusted_certs: Trust anchors.  For ``x5u``: the first entry must be the
                       leaf cert whose thumbprint matches ``x5t#S256``.  For
                       ``x5c``: the embedded chain must terminate at (or be
                       directly issued by) one of these certs.
        log_event_id:  ``logEventId`` value to include in any discrepancy report.
        allow_unsigned: Accept ``"alg": "none"`` events.  MUST only be enabled
                       when the Logging Service policy allows unsigned events
                       (``requiredAlgorithms`` contains ``"none"`` per §5.10).
                       Defaults to False: unsigned events are rejected with a
                       ``BadAlgorithm`` report, preventing signature-stripping.

    Returns:
        ``(payload_dict, None)`` on success.
        ``(payload_dict, LogSignDiscrepancyReport)`` when verification fails.
    """
    try:
        jws = json.loads(jws_bytes)
        if not isinstance(jws, dict):
            raise ValueError("Flat JWS JSON must be a JSON object")
    except Exception as exc:
        _log.warning("verify_jws: input is not a Flat JWS JSON object: %s", exc)
        return {}, LogSignDiscrepancyReport(
            problem="OtherLogSignature",
            log_event_id=log_event_id,
            result=str(exc),
        )

    payload_b64: str = jws.get("payload", "")
    protected_b64: str = jws.get("protected", "")
    sig_b64: str = jws.get("signature", "")

    try:
        protected_header: dict = json.loads(_b64url_decode(protected_b64))
        payload_dict: dict = json.loads(_b64url_decode(payload_b64))
        if not isinstance(protected_header, dict) or not isinstance(payload_dict, dict):
            raise ValueError("protected header and payload must be JSON objects")
    except Exception as exc:
        _log.warning("verify_jws: failed to decode JWS fields: %s", exc)
        return {}, LogSignDiscrepancyReport(
            problem="OtherLogSignature",
            log_event_id=log_event_id,
            result=str(exc),
        )

    # RFC 7515 §4.1.11: extensions marked critical that we do not implement
    # MUST cause the JWS to be rejected.
    if "crit" in protected_header:
        return payload_dict, LogSignDiscrepancyReport(
            problem="OtherLogSignature",
            log_event_id=log_event_id,
            result="Unsupported critical header parameters (crit)",
        )

    alg = protected_header.get("alg", "")

    # Unsigned — acceptable per §5.10 ONLY when local policy allows "none".
    if alg == "none":
        if allow_unsigned:
            return payload_dict, None
        return payload_dict, LogSignDiscrepancyReport(
            problem="BadAlgorithm",
            log_event_id=log_event_id,
            result='alg "none" rejected: unsigned events not allowed by policy',
        )

    if alg != "EdDSA":
        return payload_dict, LogSignDiscrepancyReport(
            problem="BadAlgorithm",
            log_event_id=log_event_id,
        )

    # --- Obtain leaf certificate ---
    leaf_cert: Certificate | None = None

    if "x5c" in protected_header:
        x5c = protected_header["x5c"]
        if not x5c:
            return payload_dict, LogSignDiscrepancyReport(
                problem="NoCert",
                log_event_id=log_event_id,
            )
        try:
            chain = [
                load_der_x509_certificate(base64.b64decode(entry))
                for entry in x5c
            ]
            leaf_cert = chain[0]
        except Exception as exc:
            return payload_dict, LogSignDiscrepancyReport(
                problem="BadCertX5c",
                log_event_id=log_event_id,
                result=str(exc),
            )
        if not _cert_validity_ok(leaf_cert):
            return payload_dict, LogSignDiscrepancyReport(
                problem="BadCertX5c",
                log_event_id=log_event_id,
                result="Leaf certificate is expired or not yet valid",
            )
        if trusted_certs:
            if not _chain_is_anchored(chain, trusted_certs):
                return payload_dict, LogSignDiscrepancyReport(
                    problem="BadCertX5c",
                    log_event_id=log_event_id,
                    result="x5c chain does not terminate at a trusted certificate",
                )
        else:
            _log.warning(
                "verify_jws: no trusted_certs supplied — x5c signature checked "
                "for self-consistency only; the signer is NOT authenticated. "
                "Supply PCA trust anchors via trusted_certs for production use."
            )

    elif "x5u" in protected_header:
        if "x5t#S256" not in protected_header:
            # x5u present but x5t#S256 absent — verifier can't check integrity
            return payload_dict, LogSignDiscrepancyReport(
                problem="BadThumb",
                log_event_id=log_event_id,
            )
        if not trusted_certs:
            # Caller must fetch the URL and supply the cert
            return payload_dict, LogSignDiscrepancyReport(
                problem="BadURL",
                log_event_id=log_event_id,
                result="Certificate chain not provided; caller must resolve x5u URL",
            )
        # Verify thumbprint of the supplied cert matches the header value
        supplied_der = trusted_certs[0].public_bytes(serialization.Encoding.DER)
        expected_thumb = _b64url_encode(hashlib.sha256(supplied_der).digest())
        claimed_thumb = protected_header["x5t#S256"]
        if not isinstance(claimed_thumb, str) or not hmac.compare_digest(
            expected_thumb, claimed_thumb
        ):
            return payload_dict, LogSignDiscrepancyReport(
                problem="BadThumb",
                log_event_id=log_event_id,
                thumb_calc=expected_thumb,
            )
        leaf_cert = trusted_certs[0]
        if not _cert_validity_ok(leaf_cert):
            return payload_dict, LogSignDiscrepancyReport(
                problem="BadCertX5u",
                log_event_id=log_event_id,
                result="Certificate is expired or not yet valid",
            )

    else:
        return payload_dict, LogSignDiscrepancyReport(
            problem="NoCert",
            log_event_id=log_event_id,
        )

    # --- Verify signature ---
    signing_input = (protected_b64 + "." + payload_b64).encode()
    try:
        sig_bytes = _b64url_decode(sig_b64)
        leaf_cert.public_key().verify(sig_bytes, signing_input)
    except InvalidSignature:
        return payload_dict, LogSignDiscrepancyReport(
            problem="BadSignature",
            log_event_id=log_event_id,
        )
    except Exception as exc:
        _log.warning("verify_jws: unexpected error during signature check: %s", exc)
        return payload_dict, LogSignDiscrepancyReport(
            problem="BadSignature",
            log_event_id=log_event_id,
        )

    return payload_dict, None
