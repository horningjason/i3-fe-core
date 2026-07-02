"""PCA-traceable peer authentication for proxy-terminated mTLS (§5.4).

§5.4 Authentication:
  "Mutual Authentication MUST be used for TLS and SIP session establishment
   using a certificate traceable to the PCA."

When this process terminates TLS itself, ``security.tls.make_server_ssl_context``
enforces the client certificate at the handshake (ssl.CERT_REQUIRED).  Behind
gunicorn + UvicornWorker (or any TLS-terminating proxy) that enforcement
downgrades to CERT_OPTIONAL — the ASGI layer never sees the client cert.  This
module is the compensating control: the trusted proxy forwards the verified
client certificate in an HTTP header, and :class:`ProxyClientCertMiddleware`
re-verifies it against PCA trust anchors before any protected route runs.

╔═══════════════════════════════════════════════════════════════════════════╗
║ CRITICAL DEPLOYMENT REQUIREMENTS — the header is only as trustworthy as    ║
║ the proxy that sets it:                                                    ║
║                                                                            ║
║ 1. The proxy MUST strip the client-cert header from every client-          ║
║    originated request before injecting its own value.  If a client can    ║
║    smuggle the header through, it can impersonate any element.  (nginx:   ║
║    ``proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert;``       ║
║    always overwrites; other proxies may need an explicit strip rule.)     ║
║                                                                            ║
║ 2. This process MUST only be reachable through the proxy.  Configure      ║
║    ``TLSSettings.trusted_proxies`` with the proxy's source address(es);   ║
║    the middleware rejects the header from any other source.  If left      ║
║    empty, the header is honored from ANY source and the network layer     ║
║    (firewall, localhost bind) carries the full burden — a warning is      ║
║    logged at startup.                                                     ║
╚═══════════════════════════════════════════════════════════════════════════╝

Usage (wired automatically by ``app.factory.create_app`` when
``settings.tls.mode == MTLS`` and ``settings.tls.proxy_terminated_tls``)::

    verifier = PeerCertVerifier(load_pem_certs(ca_bundle_path))
    app.add_middleware(
        ProxyClientCertMiddleware,
        verifier=verifier,
        header_name="X-SSL-Client-Cert",
        trusted_proxies=["10.0.0.1"],
        exempt_paths={"/health"},
    )

Route handlers read the verified identity from ``request.state.verified_peer``
(a :class:`VerifiedPeer`).
"""

from __future__ import annotations

import datetime
import json
import logging
import urllib.parse
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate

_log = logging.getLogger(__name__)


class PeerAuthError(Exception):
    """Peer certificate is missing, malformed, expired, or not PCA-traceable."""


@dataclass(frozen=True)
class VerifiedPeer:
    """Identity extracted from a successfully verified peer certificate.

    i3 STA-010 §5.1: an Element/Agency identity is a FQDN and an Agent
    identity is ``agentid@agencyid`` (e.g. ``nancy@erie.psap.ny.us``) — both
    carried in the certificate's SubjectAltName.  The FQDN form is a
    ``dNSName``; the ``user@domain`` Agent form is email-shaped and X.509
    encodes it as ``rfc822Name``, NOT ``dNSName`` or ``uniformResourceIdentifier``
    — read ``san_rfc822_names`` for Agent-identified peers, not
    ``san_dns_names``.

    NG-SEC §6.23.1/§6.23.3 additionally describe an ``otherName`` SAN element
    conveying Identifier/Role/Agency-Affiliation per the PCA Certificate
    Policy.  Its ASN.1 structure is defined by that policy document (not
    reproduced in the standards text available to this library), so
    ``san_other_names`` exposes the raw ``(type_id, DER value)`` pairs
    un-decoded; callers with the PCA CP spec in hand can parse further.
    """

    subject: str                                    # RFC 4514 subject string
    common_name: str | None = None                  # subject CN, if present
    san_dns_names: list[str] = field(default_factory=list)
    san_uris: list[str] = field(default_factory=list)
    # Agent identity per §5.1 (user@domain) — X.509 rfc822Name SAN entries.
    san_rfc822_names: list[str] = field(default_factory=list)
    # Raw otherName SAN entries: (dotted-string OID, DER-encoded value).
    san_other_names: list[tuple[str, bytes]] = field(default_factory=list)
    certificate: Certificate | None = None          # the verified leaf


def load_pem_certs(path) -> list[Certificate]:
    """Load one or more PEM certificates from a bundle file."""
    data = open(path, "rb").read()
    certs = x509.load_pem_x509_certificates(data)
    if not certs:
        raise ValueError(f"No PEM certificates found in {path}")
    return certs


def extract_cert_from_header(value: str) -> Certificate:
    """Decode a proxy-forwarded client certificate header into a Certificate.

    Accepts:
      • URL-encoded PEM — nginx ``$ssl_client_escaped_cert`` (the common case).
      • Plain PEM (already-decoded, possibly with spaces where newlines were,
        as some proxies fold header lines).

    Raises:
        PeerAuthError: when the value cannot be decoded into an X.509 cert.
    """
    if not value or not value.strip():
        raise PeerAuthError("Client certificate header is empty")
    try:
        decoded = urllib.parse.unquote(value)
        if "-----BEGIN CERTIFICATE-----" not in decoded:
            raise ValueError("No PEM certificate delimiter found")
        # Some proxies fold PEM newlines into spaces; restore them so the
        # base64 body parses.  The header/footer lines contain spaces of
        # their own, so normalise those back afterwards.
        if "\n" not in decoded:
            decoded = (
                decoded.replace(" ", "\n")
                .replace("-----BEGIN\nCERTIFICATE-----", "-----BEGIN CERTIFICATE-----")
                .replace("-----END\nCERTIFICATE-----", "-----END CERTIFICATE-----")
            )
        return x509.load_pem_x509_certificate(decoded.encode())
    except PeerAuthError:
        raise
    except Exception as exc:
        raise PeerAuthError(f"Cannot decode client certificate header: {exc}") from exc


class PeerCertVerifier:
    """Verifies a peer certificate chains to a PCA-traceable trust anchor (§5.4).

    Args:
        trust_anchors:  PCA-traceable anchor certificates.  A peer cert is
                        accepted when it byte-matches an anchor or chains up
                        to one (directly or via supplied intermediates).
        check_validity: Also require the peer cert to be within its
                        notBefore/notAfter window.  Defaults to True.
    """

    def __init__(
        self,
        trust_anchors: list[Certificate],
        *,
        check_validity: bool = True,
    ) -> None:
        if not trust_anchors:
            raise ValueError("PeerCertVerifier requires at least one trust anchor")
        self._anchors = list(trust_anchors)
        self._anchor_ders = {
            a.public_bytes(serialization.Encoding.DER) for a in trust_anchors
        }
        self._check_validity = check_validity

    def verify(
        self,
        cert: Certificate,
        intermediates: list[Certificate] | None = None,
    ) -> VerifiedPeer:
        """Verify *cert* and return the peer identity.

        Raises:
            PeerAuthError: expired / not yet valid / not traceable to an anchor.
        """
        if self._check_validity:
            now = datetime.datetime.now(datetime.timezone.utc)
            if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
                raise PeerAuthError(
                    "Peer certificate is expired or not yet valid "
                    f"(notBefore={cert.not_valid_before_utc.isoformat()}, "
                    f"notAfter={cert.not_valid_after_utc.isoformat()})"
                )

        if not self._is_anchored(cert, intermediates or []):
            raise PeerAuthError(
                "Peer certificate is not traceable to a configured PCA trust "
                "anchor (§5.4)"
            )

        return self._extract_identity(cert)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _is_anchored(
        self, leaf: Certificate, intermediates: list[Certificate]
    ) -> bool:
        """Walk issuer signatures from *leaf* toward a trust anchor."""
        current = leaf
        remaining = list(intermediates)
        for _ in range(len(intermediates) + 1):
            if current.public_bytes(serialization.Encoding.DER) in self._anchor_ders:
                return True
            for anchor in self._anchors:
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

    @staticmethod
    def _extract_identity(cert: Certificate) -> VerifiedPeer:
        cn: str | None = None
        cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if cn_attrs:
            cn = str(cn_attrs[0].value)

        dns_names: list[str] = []
        uris: list[str] = []
        rfc822_names: list[str] = []
        other_names: list[tuple[str, bytes]] = []
        try:
            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            dns_names = san.get_values_for_type(x509.DNSName)
            uris = [str(u) for u in san.get_values_for_type(x509.UniformResourceIdentifier)]
            # §5.1 Agent identity ("agentid@agencyid") is email-shaped and
            # X.509 carries it as rfc822Name, not dNSName or URI.
            rfc822_names = list(san.get_values_for_type(x509.RFC822Name))
            other_names = [
                (on.type_id.dotted_string, on.value)
                for on in san.get_values_for_type(x509.OtherName)
            ]
        except x509.ExtensionNotFound:
            pass

        return VerifiedPeer(
            subject=cert.subject.rfc4514_string(),
            common_name=cn,
            san_dns_names=list(dns_names),
            san_uris=uris,
            san_rfc822_names=rfc822_names,
            san_other_names=other_names,
            certificate=cert,
        )


class ProxyClientCertMiddleware:
    """ASGI middleware enforcing §5.4 mutual auth via a proxy-forwarded cert.

    For every HTTP request (except *exempt_paths*):
      1. Reject (403) when the request did not arrive from a trusted proxy
         (only enforced when *trusted_proxies* is non-empty).
      2. Reject (403) when the client-cert header is absent.
      3. Reject (403) when the forwarded cert is malformed, expired, or not
         traceable to a PCA trust anchor.
      4. On success, stash the :class:`VerifiedPeer` in
         ``scope["state"]["verified_peer"]`` (``request.state.verified_peer``).

    Exempt paths (e.g. ``/health`` for liveness probes) pass through without
    verification and without a ``verified_peer``.

    See the module docstring for the CRITICAL header-stripping and
    trusted-source deployment requirements.
    """

    def __init__(
        self,
        app,
        *,
        verifier: PeerCertVerifier,
        header_name: str,
        trusted_proxies: list[str] | None = None,
        exempt_paths: set[str] | None = None,
    ) -> None:
        self.app = app
        self._verifier = verifier
        self._header = header_name.lower().encode()
        self._trusted_proxies = frozenset(trusted_proxies or [])
        self._exempt_paths = exempt_paths or set()
        if not self._trusted_proxies:
            _log.warning(
                "ProxyClientCertMiddleware: trusted_proxies is empty — the "
                "%s header will be honored from ANY source.  The network "
                "layer MUST guarantee that only the TLS-terminating proxy "
                "can reach this process (see security/peer_auth.py).",
                header_name,
            )

    # NG-SEC §6.2.3: "Failed authentications SHALL NOT identify the reason
    # for the failure."  Every rejection path below returns this one message
    # so a caller cannot distinguish "wrong network path" from "no cert" from
    # "invalid cert" — the specific reason is logged server-side only.
    _GENERIC_DENIAL = "Forbidden"

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope["path"] in self._exempt_paths:
            await self.app(scope, receive, send)
            return

        # Guard 1: header only honored on connections from the trusted proxy.
        if self._trusted_proxies:
            client = scope.get("client")
            client_host = client[0] if client else None
            if client_host not in self._trusted_proxies:
                _log.warning(
                    "Rejected request to %s: source %r is not a trusted proxy",
                    scope["path"],
                    client_host,
                )
                await self._forbid(send)
                return

        # Guard 2 + 3: header must be present and carry a PCA-traceable cert.
        header_value: str | None = None
        for name, value in scope.get("headers", []):
            if name == self._header:
                header_value = value.decode("latin-1")
                break

        if header_value is None:
            _log.warning(
                "Rejected request to %s: no client certificate header present",
                scope["path"],
            )
            await self._forbid(send)
            return

        try:
            cert = extract_cert_from_header(header_value)
            peer = self._verifier.verify(cert)
        except PeerAuthError as exc:
            _log.warning(
                "Rejected request to %s: client certificate verification "
                "failed: %s",
                scope["path"],
                exc,
            )
            await self._forbid(send)
            return

        scope.setdefault("state", {})["verified_peer"] = peer
        await self.app(scope, receive, send)

    async def _forbid(self, send) -> None:
        body = json.dumps({"detail": self._GENERIC_DENIAL}).encode()
        await send({
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": body})
