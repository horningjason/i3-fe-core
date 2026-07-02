"""TLS/mTLS context helpers for i3 inter-FE HTTP (§2.8.1).

§2.8.1 Requirements:
  • i3 services MUST support HTTPS (RFC 2818) — §2.8.1
  • Clients and servers MUST support TLS 1.2 — §2.8.1
  • MAY support TLS 1.3 or greater — §2.8.1
  • MUST NOT offer or accept TLS 1.1 or TLS 1.0 — §2.8.1
  • Perfect forward secrecy MUST be used within the ESInet — §2.8.1

PFS implementation note:
  TLS 1.3 cipher suites are fixed by RFC 8446 and are always PFS-capable
  (all use ECDHE key exchange).  For TLS 1.2, this module selects only
  ECDHE and DHE cipher suites; static RSA key exchange (which does not
  provide PFS) is excluded.

ENVIRONMENT CAVEAT — gunicorn + UvicornWorker:
  When deployed behind gunicorn with UvicornWorker, TLS terminates at
  gunicorn before uvicorn/Starlette sees the connection.
  ssl.CERT_REQUIRED is therefore unreliable for mTLS: gunicorn may not
  forward the client certificate to uvicorn, silently downgrading to
  CERT_OPTIONAL behaviour.

  Use ``make_server_ssl_context(settings, gunicorn_mode=True)`` to
  acknowledge this limitation explicitly.  It sets CERT_OPTIONAL and logs
  a clear warning so operators know mTLS is not enforced at the handshake
  layer.  The compensating control lives in ``security/peer_auth.py``:
  set ``TLSSettings.proxy_terminated_tls=True`` and ``client_cert_header``
  and the app factory verifies the proxy-forwarded client certificate
  against PCA trust anchors at the application layer.  See §2.8 and §5.4.
"""

from __future__ import annotations

import logging
import ssl

from i3_fe_core.config.settings import TLSMode, TLSSettings

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PFS cipher suite string for TLS 1.2 (TLS 1.3 cipher suites are immutable).
# Selects ECDHE and DHE key-exchange groups; excludes:
#   aNULL  — anonymous (no authentication)
#   eNULL  — no encryption
#   3DES   — Triple-DES (SWEET32 vulnerability)
#   RC4    — stream cipher (known-weak)
#   MD5    — weak hash
#   DSS    — DSA (uncommon, avoid)
# ---------------------------------------------------------------------------
_PFS_CIPHERS_TLS12: str = (
    "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20"
    ":!aNULL:!eNULL:!3DES:!RC4:!MD5:!DSS"
)


def _apply_tls_constraints(ctx: ssl.SSLContext) -> None:
    """Enforce §2.8.1 TLS requirements on *ctx* (both server and client).

    On Python 3.10+ (which i3-fe-core requires ≥3.11), ``minimum_version``
    is the authoritative and recommended way to restrict TLS versions.
    The deprecated ``OP_NO_TLSv1`` / ``OP_NO_TLSv1_1`` options are NOT set
    here because they are superseded by ``minimum_version`` and trigger
    DeprecationWarnings in Python 3.10+.
    """
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_ciphers(_PFS_CIPHERS_TLS12)
    except ssl.SSLError as exc:
        _log.warning(
            "Could not restrict to PFS-only TLS 1.2 ciphers (%s). "
            "The platform's default ciphers will be used; TLS 1.3 is "
            "unaffected (always PFS). Verify the deployed cipher suite "
            "meets §2.8.1 PFS requirements for this deployment.",
            exc,
        )


def make_server_ssl_context(
    settings: TLSSettings,
    *,
    gunicorn_mode: bool = False,
) -> ssl.SSLContext | None:
    """Build a server-side ``ssl.SSLContext`` from *settings*.

    Returns ``None`` when ``settings.mode`` is TLSMode.OFF (plain HTTP).

    The returned context:
      • Enforces TLS 1.2 minimum (§2.8.1).
      • Disables TLS 1.0 and TLS 1.1 (§2.8.1).
      • Selects ECDHE/DHE cipher suites for PFS (§2.8.1).
      • Loads the server certificate and key when ``cert_path`` is set.
      • In MTLS mode: loads the CA for client-certificate verification and
        sets CERT_REQUIRED (or CERT_OPTIONAL under gunicorn — see caveat).

    Args:
        settings:      TLS settings from ``CoreSettings.tls``.
        gunicorn_mode: Set ``True`` when running behind gunicorn+UvicornWorker
                       to acknowledge the mTLS limitation and avoid a false
                       claim of CERT_REQUIRED enforcement (module docstring).
    """
    if settings.mode == TLSMode.OFF:
        return None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    _apply_tls_constraints(ctx)

    if settings.cert_path is not None:
        ctx.load_cert_chain(
            certfile=str(settings.cert_path),
            keyfile=str(settings.key_path) if settings.key_path else None,
        )

    if settings.mode == TLSMode.MTLS:
        if settings.ca_path is None:
            # Without a CA bundle, client certificates can never be verified:
            # CERT_REQUIRED would reject every handshake, and CERT_OPTIONAL
            # (gunicorn_mode) would silently skip verification entirely.
            raise ValueError(
                "TLSMode.MTLS requires ca_path — client certificates cannot "
                "be verified without a CA bundle (§2.8)"
            )
        ctx.load_verify_locations(cafile=str(settings.ca_path))

        if gunicorn_mode:
            _log.warning(
                "gunicorn+UvicornWorker: TLS terminates at gunicorn before "
                "uvicorn sees the connection — ssl.CERT_REQUIRED cannot be "
                "enforced at the ASGI layer.  Falling back to CERT_OPTIONAL. "
                "Add a compensating control (e.g. verify X-SSL-Client-Cert "
                "header from the trusted TLS proxy) at the application layer. "
                "See §2.8 ENVIRONMENT CAVEAT in security/tls.py."
            )
            ctx.verify_mode = ssl.CERT_OPTIONAL
        else:
            ctx.verify_mode = ssl.CERT_REQUIRED

    return ctx


def make_client_ssl_context(settings: TLSSettings) -> ssl.SSLContext:
    """Build an outbound SSL context for HTTP calls to peer FEs (§2.8.1).

    Always verifies the peer's server certificate
    (``ssl.Purpose.SERVER_AUTH`` semantics).  In MTLS mode, also loads
    this element's PCA-traceable client certificate and key so the peer
    can authenticate the caller.

    Returns an ``ssl.SSLContext`` suitable for ``httpx.AsyncClient(verify=…)``.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    _apply_tls_constraints(ctx)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED  # always verify peer

    if settings.ca_path is not None:
        ctx.load_verify_locations(cafile=str(settings.ca_path))
    else:
        # No explicit CA bundle — fall back to the platform trust store so the
        # context has usable trust anchors (an empty store rejects every peer,
        # which pressures operators into disabling verification).
        ctx.load_default_certs(ssl.Purpose.SERVER_AUTH)

    if settings.mode == TLSMode.MTLS and settings.cert_path is not None:
        ctx.load_cert_chain(
            certfile=str(settings.cert_path),
            keyfile=str(settings.key_path) if settings.key_path else None,
        )

    return ctx
