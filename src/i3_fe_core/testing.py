"""Test-only credential helpers for i3-fe-core and FE test suites.

FOR TEST CODE ONLY.  This module is intentionally kept out of the
``logging`` / ``security`` production import paths so that a self-signed,
non-PCA-traceable credential can never be reached from a production code
path by accident (NG-SEC NENA-STA-040.2-2024 §6.23.8: self-signed
certificates MUST NOT be used for ESInet communications; §6.9: production
environments SHALL NOT contain development tools).

Nothing in this module changes how certificates are *verified* — a
self-signed certificate you generate here (or in your own test fixtures)
continues to verify normally through ``JwsSigner``/``verify_jws`` or
``PeerCertVerifier`` when you explicitly supply it as a trust anchor, exactly
as real PCA-issued certificates do.  This module only controls where the
convenience generator lives, not what the verifiers accept.

Usage (test code)::

    from i3_fe_core.testing import make_test_credential

    key, cert = make_test_credential()
    signer = JwsSigner(private_key=key, cert_chain=[cert])
    payload, report = verify_jws(signer.sign(body), trusted_certs=[cert])
"""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID

__all__ = ["make_test_credential"]


def make_test_credential() -> tuple[Ed448PrivateKey, Certificate]:
    """Generate a throwaway Ed448 key pair and self-signed certificate.

    FOR TESTING ONLY — the returned certificate is NOT PCA-traceable and
    MUST NOT be used in a production ESInet.

    Returns:
        ``(private_key, self_signed_cert)`` — both in-memory only.
    """
    private_key = Ed448PrivateKey.generate()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "i3-fe-core-test-element"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2034, 1, 1, tzinfo=datetime.timezone.utc))
        .sign(private_key, None)   # Ed448 has no separate hash algorithm
    )
    return private_key, cert
