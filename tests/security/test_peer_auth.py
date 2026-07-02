"""Tests for security/peer_auth.py — §5.4 PCA-traceable peer authentication.

Covers PeerCertVerifier, extract_cert_from_header, ProxyClientCertMiddleware,
and the create_app() wiring (proxy-terminated mTLS compensating control).
"""

from __future__ import annotations

import datetime
import urllib.parse

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.x509.oid import NameOID
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.testclient import TestClient

from i3_fe_core.app.factory import create_app
from i3_fe_core.config.identity import ElementIdentity
from i3_fe_core.config.settings import CoreSettings, TLSMode, TLSSettings
from i3_fe_core.security.peer_auth import (
    PeerAuthError,
    PeerCertVerifier,
    VerifiedPeer,
    extract_cert_from_header,
    load_pem_certs,
)


# ---------------------------------------------------------------------------
# Certificate helpers — in-memory Ed448 CA and CA-issued leaves
# ---------------------------------------------------------------------------

_UTC = datetime.timezone.utc


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _make_ca(cn: str = "test-pca-root"):
    key = Ed448PrivateKey.generate()
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=_UTC))
        .not_valid_after(datetime.datetime(2034, 1, 1, tzinfo=_UTC))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, None)
    )
    return key, cert


def _make_leaf(
    ca_key: Ed448PrivateKey,
    ca_cert: x509.Certificate,
    cn: str = "ecrf.psap.allegheny.pa.us",
    *,
    expired: bool = False,
):
    key = Ed448PrivateKey.generate()
    not_before = datetime.datetime(2024, 1, 1, tzinfo=_UTC)
    not_after = (
        datetime.datetime(2025, 1, 1, tzinfo=_UTC)   # already past (today ≥ 2026)
        if expired
        else datetime.datetime(2034, 1, 1, tzinfo=_UTC)
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False
        )
        .sign(ca_key, None)
    )
    return key, cert


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _header_value(cert: x509.Certificate) -> str:
    """URL-encoded PEM — what nginx's $ssl_client_escaped_cert produces."""
    return urllib.parse.quote(_pem(cert))


@pytest.fixture(scope="module")
def pca():
    """(ca_key, ca_cert) shared across the module — Ed448 keygen is slow-ish."""
    return _make_ca()


@pytest.fixture(scope="module")
def leaf(pca):
    ca_key, ca_cert = pca
    return _make_leaf(ca_key, ca_cert)


# ---------------------------------------------------------------------------
# PeerCertVerifier
# ---------------------------------------------------------------------------

def test_verifier_requires_trust_anchors():
    with pytest.raises(ValueError, match="trust anchor"):
        PeerCertVerifier([])


def test_verifier_accepts_pca_issued_leaf(pca, leaf):
    _, ca_cert = pca
    _, leaf_cert = leaf
    peer = PeerCertVerifier([ca_cert]).verify(leaf_cert)
    assert isinstance(peer, VerifiedPeer)
    assert peer.common_name == "ecrf.psap.allegheny.pa.us"
    assert "ecrf.psap.allegheny.pa.us" in peer.san_dns_names


def test_verifier_accepts_anchor_cert_itself(pca):
    _, ca_cert = pca
    peer = PeerCertVerifier([ca_cert]).verify(ca_cert)
    assert peer.common_name == "test-pca-root"


def test_verifier_rejects_untraceable_cert(pca):
    _, ca_cert = pca
    rogue_key, rogue_ca = _make_ca("rogue-ca")
    _, rogue_leaf = _make_leaf(rogue_key, rogue_ca, "attacker.example.com")
    with pytest.raises(PeerAuthError, match="not traceable"):
        PeerCertVerifier([ca_cert]).verify(rogue_leaf)


def test_verifier_rejects_expired_cert(pca):
    ca_key, ca_cert = pca
    _, expired_leaf = _make_leaf(ca_key, ca_cert, expired=True)
    with pytest.raises(PeerAuthError, match="expired"):
        PeerCertVerifier([ca_cert]).verify(expired_leaf)


def test_verifier_check_validity_false_allows_expired(pca):
    ca_key, ca_cert = pca
    _, expired_leaf = _make_leaf(ca_key, ca_cert, expired=True)
    peer = PeerCertVerifier([ca_cert], check_validity=False).verify(expired_leaf)
    assert peer.common_name == "ecrf.psap.allegheny.pa.us"


def test_verifier_walks_intermediate_chain(pca):
    """leaf ← intermediate ← anchor must verify when intermediates supplied."""
    ca_key, ca_cert = pca
    int_key = Ed448PrivateKey.generate()
    int_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("test-intermediate"))
        .issuer_name(ca_cert.subject)
        .public_key(int_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=_UTC))
        .not_valid_after(datetime.datetime(2034, 1, 1, tzinfo=_UTC))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, None)
    )
    _, leaf_cert = _make_leaf(int_key, int_cert, "lvf.psap.allegheny.pa.us")

    verifier = PeerCertVerifier([ca_cert])
    peer = verifier.verify(leaf_cert, intermediates=[int_cert])
    assert peer.common_name == "lvf.psap.allegheny.pa.us"
    # Without the intermediate, the leaf is not traceable.
    with pytest.raises(PeerAuthError):
        verifier.verify(leaf_cert)


# ---------------------------------------------------------------------------
# extract_cert_from_header
# ---------------------------------------------------------------------------

def test_extract_url_encoded_pem_roundtrip(leaf):
    _, leaf_cert = leaf
    cert = extract_cert_from_header(_header_value(leaf_cert))
    assert cert == leaf_cert


def test_extract_plain_pem(leaf):
    _, leaf_cert = leaf
    cert = extract_cert_from_header(_pem(leaf_cert))
    assert cert == leaf_cert


def test_extract_space_folded_pem(leaf):
    """Some proxies fold PEM newlines into spaces when forwarding headers."""
    _, leaf_cert = leaf
    folded = _pem(leaf_cert).strip().replace("\n", " ")
    cert = extract_cert_from_header(folded)
    assert cert == leaf_cert


def test_extract_empty_header_raises():
    with pytest.raises(PeerAuthError, match="empty"):
        extract_cert_from_header("   ")


def test_extract_garbage_raises():
    with pytest.raises(PeerAuthError, match="decode"):
        extract_cert_from_header("definitely-not-a-certificate")


# ---------------------------------------------------------------------------
# load_pem_certs
# ---------------------------------------------------------------------------

def test_load_pem_certs_reads_bundle(tmp_path, pca, leaf):
    _, ca_cert = pca
    _, leaf_cert = leaf
    bundle = tmp_path / "bundle.pem"
    bundle.write_text(_pem(ca_cert) + _pem(leaf_cert))
    certs = load_pem_certs(bundle)
    assert len(certs) == 2


def test_load_pem_certs_empty_file_raises(tmp_path):
    empty = tmp_path / "empty.pem"
    empty.write_text("")
    with pytest.raises(Exception):
        load_pem_certs(empty)


# ---------------------------------------------------------------------------
# ProxyClientCertMiddleware via create_app (§5.4 wiring)
# ---------------------------------------------------------------------------

def _identity() -> ElementIdentity:
    return ElementIdentity(
        element_id="ecrf.psap.allegheny.pa.us",
        agency_id="psap.allegheny.pa.us",
        agent_id="dispatcher1",
        service_id="ecrf.psap.allegheny.pa.us",
        service_name="ECRF",
    )


class _FakeNtpClient:
    is_healthy: bool = True
    offset: float | None = 0.001

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass


class _FakeLoggingClient:
    async def emit(self, event) -> dict:
        return {}


def _proxy_mtls_app(tmp_path, ca_cert, *, trusted_proxies=None, register_routes=None):
    anchor = tmp_path / "pca.pem"
    anchor.write_text(_pem(ca_cert))
    settings = CoreSettings(
        tls=TLSSettings(
            mode=TLSMode.MTLS,
            ca_path=anchor,
            proxy_terminated_tls=True,
            client_cert_header="X-SSL-Client-Cert",
            pca_trust_anchors=[anchor],
            trusted_proxies=trusted_proxies or [],
        ),
    )
    return create_app(
        identity=_identity(),
        settings=settings,
        register_routes=register_routes or (lambda app: None),
        ntp_client=_FakeNtpClient(),
        logging_client=_FakeLoggingClient(),
        ntp_check_interval=9999.0,
    )


def test_valid_pca_cert_header_gets_200_and_identity_on_scope(tmp_path, pca, leaf):
    _, ca_cert = pca
    _, leaf_cert = leaf

    async def whoami(request: Request) -> JSONResponse:
        peer: VerifiedPeer = request.state.verified_peer
        return JSONResponse({"cn": peer.common_name})

    def register(app):
        app.add_route("/whoami", whoami, methods=["GET"])

    app = _proxy_mtls_app(tmp_path, ca_cert, register_routes=register)
    with TestClient(app) as client:
        headers = {"X-SSL-Client-Cert": _header_value(leaf_cert)}
        assert client.get("/ElementState", headers=headers).status_code == 200
        assert client.get("/ServiceState", headers=headers).status_code == 200
        resp = client.get("/whoami", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["cn"] == "ecrf.psap.allegheny.pa.us"


def test_missing_cert_header_rejected_403(tmp_path, pca):
    _, ca_cert = pca
    app = _proxy_mtls_app(tmp_path, ca_cert)
    with TestClient(app) as client:
        assert client.get("/ElementState").status_code == 403
        assert client.get("/ServiceState").status_code == 403


def test_health_stays_open_without_cert(tmp_path, pca):
    """Liveness probes must work without a client certificate."""
    _, ca_cert = pca
    app = _proxy_mtls_app(tmp_path, ca_cert)
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200


def test_expired_cert_rejected_403(tmp_path, pca):
    ca_key, ca_cert = pca
    _, expired_leaf = _make_leaf(ca_key, ca_cert, expired=True)
    app = _proxy_mtls_app(tmp_path, ca_cert)
    with TestClient(app) as client:
        resp = client.get(
            "/ElementState", headers={"X-SSL-Client-Cert": _header_value(expired_leaf)}
        )
    assert resp.status_code == 403


def test_untraceable_cert_rejected_403(tmp_path, pca):
    _, ca_cert = pca
    rogue_key, rogue_ca = _make_ca("rogue-ca")
    _, rogue_leaf = _make_leaf(rogue_key, rogue_ca, "attacker.example.com")
    app = _proxy_mtls_app(tmp_path, ca_cert)
    with TestClient(app) as client:
        resp = client.get(
            "/ElementState", headers={"X-SSL-Client-Cert": _header_value(rogue_leaf)}
        )
    assert resp.status_code == 403


def test_malformed_cert_header_rejected_403(tmp_path, pca):
    _, ca_cert = pca
    app = _proxy_mtls_app(tmp_path, ca_cert)
    with TestClient(app) as client:
        resp = client.get(
            "/ElementState", headers={"X-SSL-Client-Cert": "garbage"}
        )
    assert resp.status_code == 403


def test_header_from_untrusted_source_rejected(tmp_path, pca, leaf):
    """Guard: the header is only honored on connections from the trusted proxy.

    Starlette's TestClient presents client host "testclient"; pinning
    trusted_proxies to a different address must reject even a valid cert.
    """
    _, ca_cert = pca
    _, leaf_cert = leaf
    app = _proxy_mtls_app(tmp_path, ca_cert, trusted_proxies=["10.0.0.1"])
    with TestClient(app) as client:
        resp = client.get(
            "/ElementState", headers={"X-SSL-Client-Cert": _header_value(leaf_cert)}
        )
    assert resp.status_code == 403


def test_header_from_trusted_source_accepted(tmp_path, pca, leaf):
    _, ca_cert = pca
    _, leaf_cert = leaf
    app = _proxy_mtls_app(tmp_path, ca_cert, trusted_proxies=["testclient"])
    with TestClient(app) as client:
        resp = client.get(
            "/ElementState", headers={"X-SSL-Client-Cert": _header_value(leaf_cert)}
        )
    assert resp.status_code == 200


def test_header_ignored_when_proxy_mode_off(tmp_path, pca, leaf):
    """Without proxy_terminated_tls the middleware is not installed at all."""
    _, ca_cert = pca
    _, leaf_cert = leaf
    anchor = tmp_path / "pca.pem"
    anchor.write_text(_pem(ca_cert))
    settings = CoreSettings(
        tls=TLSSettings(mode=TLSMode.MTLS, ca_path=anchor),  # no proxy mode
    )
    app = create_app(
        identity=_identity(),
        settings=settings,
        register_routes=lambda app: None,
        ntp_client=_FakeNtpClient(),
        logging_client=_FakeLoggingClient(),
        ntp_check_interval=9999.0,
    )
    with TestClient(app) as client:
        # Header present or absent makes no difference; no 403 gating.
        assert client.get("/ElementState").status_code == 200
        resp = client.get(
            "/ElementState", headers={"X-SSL-Client-Cert": _header_value(leaf_cert)}
        )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# TLSSettings validation for proxy-terminated mTLS
# ---------------------------------------------------------------------------

def test_settings_proxy_mode_requires_header():
    with pytest.raises(ValueError, match="client_cert_header"):
        TLSSettings(
            mode=TLSMode.MTLS,
            proxy_terminated_tls=True,
            pca_trust_anchors=["anchors.pem"],
        )


def test_settings_proxy_mode_requires_trust_anchors():
    with pytest.raises(ValueError, match="pca_trust_anchors"):
        TLSSettings(
            mode=TLSMode.MTLS,
            proxy_terminated_tls=True,
            client_cert_header="X-SSL-Client-Cert",
        )


def test_settings_proxy_mode_accepts_ca_path_as_anchor_fallback(tmp_path):
    settings = TLSSettings(
        mode=TLSMode.MTLS,
        proxy_terminated_tls=True,
        client_cert_header="X-SSL-Client-Cert",
        ca_path=tmp_path / "ca.pem",
    )
    assert settings.proxy_terminated_tls is True


# ---------------------------------------------------------------------------
# §5.1 Agent identity (rfc822Name) and NG-SEC §6.23.1/.3 otherName extraction
# ---------------------------------------------------------------------------

def _make_agent_leaf(ca_key: Ed448PrivateKey, ca_cert: x509.Certificate):
    """A leaf carrying an rfc822Name (Agent identity) and an otherName SAN.

    i3 STA-010 §5.1: Agent identity is "agentid@agencyid" and is carried as
    an rfc822Name SAN entry (it is email-shaped, not a DNSName or URI).
    """
    key = Ed448PrivateKey.generate()
    other_name_oid = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1")
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("nancy@erie.psap.ny.us"))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=_UTC))
        .not_valid_after(datetime.datetime(2034, 1, 1, tzinfo=_UTC))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.RFC822Name("nancy@erie.psap.ny.us"),
                x509.OtherName(other_name_oid, b"\x0c\x04role"),  # UTF8String "role"
            ]),
            critical=False,
        )
        .sign(ca_key, None)
    )
    return key, cert


def test_verifier_extracts_agent_rfc822_name(pca):
    """Agent identity (user@domain) must come back on san_rfc822_names, not DNS/URI."""
    ca_key, ca_cert = pca
    _, agent_leaf = _make_agent_leaf(ca_key, ca_cert)
    peer = PeerCertVerifier([ca_cert]).verify(agent_leaf)
    assert peer.san_rfc822_names == ["nancy@erie.psap.ny.us"]
    assert peer.san_dns_names == []  # not misfiled as a DNSName


def test_verifier_extracts_other_name_san(pca):
    """otherName SAN entries (NG-SEC §6.23.1/.3 Identifier/Role/Agency) are exposed raw."""
    ca_key, ca_cert = pca
    _, agent_leaf = _make_agent_leaf(ca_key, ca_cert)
    peer = PeerCertVerifier([ca_cert]).verify(agent_leaf)
    assert len(peer.san_other_names) == 1
    oid, value = peer.san_other_names[0]
    assert oid == "1.3.6.1.4.1.99999.1"
    assert value == b"\x0c\x04role"


def test_verifier_dns_only_leaf_has_empty_agent_fields(pca, leaf):
    """A pure FE/service cert (DNSName only) has no Agent-identity fields set."""
    _, ca_cert = pca
    _, leaf_cert = leaf
    peer = PeerCertVerifier([ca_cert]).verify(leaf_cert)
    assert peer.san_rfc822_names == []
    assert peer.san_other_names == []


# ---------------------------------------------------------------------------
# NG-SEC §6.2.3: failed authentications must not reveal the failure reason
# ---------------------------------------------------------------------------

def test_missing_and_invalid_cert_return_identical_denial_body(tmp_path, pca):
    """Missing header vs. untraceable cert must be indistinguishable to the caller."""
    _, ca_cert = pca
    rogue_key, rogue_ca = _make_ca("rogue-ca-2")
    _, rogue_leaf = _make_leaf(rogue_key, rogue_ca, "attacker2.example.com")

    app = _proxy_mtls_app(tmp_path, ca_cert)
    with TestClient(app) as client:
        missing = client.get("/ElementState")
        invalid = client.get(
            "/ElementState", headers={"X-SSL-Client-Cert": _header_value(rogue_leaf)}
        )
        malformed = client.get(
            "/ElementState", headers={"X-SSL-Client-Cert": "garbage"}
        )

    assert missing.status_code == invalid.status_code == malformed.status_code == 403
    assert missing.json() == invalid.json() == malformed.json()
    assert "detail" in missing.json()


def test_untrusted_source_returns_same_denial_body_as_missing_cert(tmp_path, pca):
    _, ca_cert = pca
    app_pinned = _proxy_mtls_app(tmp_path, ca_cert, trusted_proxies=["10.0.0.1"])
    app_open = _proxy_mtls_app(tmp_path, ca_cert)

    with TestClient(app_pinned) as client:
        untrusted_source_resp = client.get("/ElementState")
    with TestClient(app_open) as client:
        missing_cert_resp = client.get("/ElementState")

    assert untrusted_source_resp.status_code == missing_cert_resp.status_code == 403
    assert untrusted_source_resp.json() == missing_cert_resp.json()


# ---------------------------------------------------------------------------
# i3_fe_core.testing — test-only credential helper lives outside jws_signer
# ---------------------------------------------------------------------------

def test_make_test_credential_not_importable_from_jws_signer():
    """§6.23.8/§6.9: the test-cert generator must not be in the prod import path."""
    from i3_fe_core.logging import jws_signer
    assert not hasattr(jws_signer, "make_test_credential")


def test_make_test_credential_importable_from_testing_module():
    from i3_fe_core.testing import make_test_credential
    key, cert = make_test_credential()
    assert key is not None
    assert cert is not None
