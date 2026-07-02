"""Tests for security/tls.py — §2.8.1 TLS requirements.

All tests are pure unit tests — no network, no real certificate files.
We verify the SSL context is *configured* correctly; negotiation is
tested via context options and minimum_version properties.
"""

from __future__ import annotations

import ssl
import logging

import pytest

from i3_fe_core.config.settings import TLSMode, TLSSettings
from i3_fe_core.security.tls import (
    _PFS_CIPHERS_TLS12,
    _apply_tls_constraints,
    make_client_ssl_context,
    make_server_ssl_context,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def ca_file(tmp_path):
    """A real (self-signed, test-only) CA certificate on disk in PEM form."""
    from cryptography.hazmat.primitives.serialization import Encoding
    from i3_fe_core.testing import make_test_credential
    _, cert = make_test_credential()
    path = tmp_path / "ca.pem"
    path.write_bytes(cert.public_bytes(Encoding.PEM))
    return path


# ---------------------------------------------------------------------------
# make_server_ssl_context — mode=OFF
# ---------------------------------------------------------------------------

def test_server_context_off_returns_none():
    """TLSMode.OFF must return None (no SSL context — plain HTTP)."""
    ctx = make_server_ssl_context(TLSSettings(mode=TLSMode.OFF))
    assert ctx is None


# ---------------------------------------------------------------------------
# make_server_ssl_context — TLS 1.2 minimum enforcement (§2.8.1)
# ---------------------------------------------------------------------------

def test_server_context_minimum_version_is_tls12():
    """§2.8.1: MUST support TLS 1.2 and enforce it as the minimum version."""
    ctx = make_server_ssl_context(TLSSettings(mode=TLSMode.TLS))
    assert ctx is not None
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_server_context_no_tls10():
    """§2.8.1: MUST NOT offer or accept TLS 1.0.

    Enforced via minimum_version = TLSv1_2, which excludes TLS 1.0 and 1.1.
    (The deprecated OP_NO_TLSv1 option is not used on Python 3.10+.)
    """
    ctx = make_server_ssl_context(TLSSettings(mode=TLSMode.TLS))
    assert ctx is not None
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_server_context_no_tls11():
    """§2.8.1: MUST NOT offer or accept TLS 1.1.

    Enforced via minimum_version = TLSv1_2, which excludes TLS 1.0 and 1.1.
    """
    ctx = make_server_ssl_context(TLSSettings(mode=TLSMode.TLS))
    assert ctx is not None
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_server_context_is_ssl_context():
    ctx = make_server_ssl_context(TLSSettings(mode=TLSMode.TLS))
    assert isinstance(ctx, ssl.SSLContext)


# ---------------------------------------------------------------------------
# make_server_ssl_context — mTLS mode
# ---------------------------------------------------------------------------

def test_server_mtls_gunicorn_mode_uses_cert_optional(caplog, ca_file):
    """gunicorn+UvicornWorker caveat: mTLS falls back to CERT_OPTIONAL."""
    with caplog.at_level(logging.WARNING, logger="i3_fe_core.security.tls"):
        ctx = make_server_ssl_context(
            TLSSettings(mode=TLSMode.MTLS, ca_path=ca_file),
            gunicorn_mode=True,
        )
    assert ctx is not None
    assert ctx.verify_mode == ssl.CERT_OPTIONAL

    # Must emit a warning so operators are aware of the downgrade.
    assert any("CERT_OPTIONAL" in r.message or "gunicorn" in r.message.lower()
               for r in caplog.records)


def test_server_mtls_standard_mode_uses_cert_required(ca_file):
    """In standard (non-gunicorn) mTLS mode, client cert is REQUIRED."""
    ctx = make_server_ssl_context(
        TLSSettings(mode=TLSMode.MTLS, ca_path=ca_file),
        gunicorn_mode=False,
    )
    assert ctx is not None
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_server_mtls_without_ca_path_raises():
    """mTLS without a CA bundle cannot verify client certs — must fail loudly."""
    with pytest.raises(ValueError, match="ca_path"):
        make_server_ssl_context(TLSSettings(mode=TLSMode.MTLS))


def test_server_mtls_gunicorn_mode_without_ca_path_raises():
    """CERT_OPTIONAL with no CA would silently skip verification — must fail loudly."""
    with pytest.raises(ValueError, match="ca_path"):
        make_server_ssl_context(TLSSettings(mode=TLSMode.MTLS), gunicorn_mode=True)


def test_server_tls_mode_does_not_require_client_cert():
    """TLS mode (server-side only) must NOT enforce client certs."""
    ctx = make_server_ssl_context(TLSSettings(mode=TLSMode.TLS))
    assert ctx is not None
    # Default for TLS-only (no mTLS): CERT_NONE or CERT_OPTIONAL, never REQUIRED.
    assert ctx.verify_mode != ssl.CERT_REQUIRED


# ---------------------------------------------------------------------------
# make_client_ssl_context
# ---------------------------------------------------------------------------

def test_client_context_minimum_version_is_tls12():
    """Client context MUST also enforce TLS 1.2 minimum (§2.8.1)."""
    ctx = make_client_ssl_context(TLSSettings(mode=TLSMode.TLS))
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_client_context_no_tls10():
    """Client MUST NOT accept TLS 1.0 connections (§2.8.1)."""
    ctx = make_client_ssl_context(TLSSettings(mode=TLSMode.TLS))
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_client_context_no_tls11():
    """Client MUST NOT accept TLS 1.1 connections (§2.8.1)."""
    ctx = make_client_ssl_context(TLSSettings(mode=TLSMode.TLS))
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_client_context_always_verifies_peer():
    """Client MUST always verify the server certificate (not CERT_NONE)."""
    ctx = make_client_ssl_context(TLSSettings(mode=TLSMode.TLS))
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_client_context_is_ssl_context():
    ctx = make_client_ssl_context(TLSSettings(mode=TLSMode.TLS))
    assert isinstance(ctx, ssl.SSLContext)


def test_client_context_without_ca_path_loads_platform_trust_store():
    """No explicit CA → platform trust anchors must be loaded (never an empty store)."""
    ctx = make_client_ssl_context(TLSSettings(mode=TLSMode.TLS))
    assert ctx.cert_store_stats()["x509_ca"] > 0


def test_client_context_with_ca_path_uses_it(ca_file):
    """Explicit CA bundle is loaded into the trust store."""
    ctx = make_client_ssl_context(TLSSettings(mode=TLSMode.TLS, ca_path=ca_file))
    assert ctx.cert_store_stats()["x509"] >= 1


# ---------------------------------------------------------------------------
# PFS cipher string format
# ---------------------------------------------------------------------------

def test_pfs_ciphers_constant_excludes_null_ciphers():
    """PFS cipher string must exclude aNULL and eNULL."""
    assert "!aNULL" in _PFS_CIPHERS_TLS12
    assert "!eNULL" in _PFS_CIPHERS_TLS12


def test_pfs_ciphers_constant_includes_ecdhe():
    """ECDHE key exchange is required for PFS (§2.8.1)."""
    assert "ECDHE" in _PFS_CIPHERS_TLS12


def test_pfs_ciphers_constant_includes_dhe():
    """DHE key exchange is also PFS-capable."""
    assert "DHE" in _PFS_CIPHERS_TLS12


# ---------------------------------------------------------------------------
# _apply_tls_constraints — shared internal helper
# ---------------------------------------------------------------------------

def test_apply_tls_constraints_sets_minimum_version():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    _apply_tls_constraints(ctx)
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_apply_tls_constraints_excludes_tls10_via_minimum_version():
    """_apply_tls_constraints must block TLS 1.0 via minimum_version."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    _apply_tls_constraints(ctx)
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_apply_tls_constraints_excludes_tls11_via_minimum_version():
    """_apply_tls_constraints must block TLS 1.1 via minimum_version."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    _apply_tls_constraints(ctx)
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
