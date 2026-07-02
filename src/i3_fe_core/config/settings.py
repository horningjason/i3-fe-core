"""FE configuration container.

CoreSettings is a plain Pydantic model — not a BaseSettings subclass — so it
carries no env-prefix or env-file logic.  The FE resolves values from its own
env prefix (or any other source) and passes them here.  Nothing in this module
reads environment variables.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import BaseModel, field_validator, model_validator


class TLSMode(str, Enum):
    """TLS operating modes for inter-FE HTTP (§2.8)."""

    OFF = "off"
    TLS = "tls"
    MTLS = "mtls"


class TLSSettings(BaseModel):
    """Paths and mode for TLS/mTLS.  Covers: NENA-STA-010.3f-2021 §2.8, §5.4.

    Proxy-terminated mTLS (§5.4 compensating control)
    --------------------------------------------------
    When TLS terminates at a proxy in front of this process (gunicorn +
    UvicornWorker, nginx, an SBC, …) the ASGI layer never sees the client
    certificate, so handshake-level mutual authentication cannot be enforced
    here.  Set ``proxy_terminated_tls=True`` and ``client_cert_header`` to the
    header the trusted proxy injects (e.g. ``X-SSL-Client-Cert`` carrying
    nginx's ``$ssl_client_escaped_cert``); the app then verifies the forwarded
    certificate against ``pca_trust_anchors`` at the application layer.

    ``trusted_proxies`` pins which source addresses the header is honored
    from.  Leave it empty ONLY when the network guarantees all traffic
    reaches this process via the proxy.
    """

    mode: TLSMode = TLSMode.OFF
    cert_path: Path | None = None
    key_path: Path | None = None
    ca_path: Path | None = None

    # --- Proxy-terminated mTLS (§5.4) ---
    # True when a trusted proxy terminates TLS and forwards the client cert
    # in an HTTP header.  Only takes effect when mode == MTLS.
    proxy_terminated_tls: bool = False
    # Header carrying the URL-encoded PEM client certificate, e.g.
    # "X-SSL-Client-Cert".  REQUIRED when proxy_terminated_tls is True.
    client_cert_header: str | None = None
    # PEM bundle paths for PCA-traceable trust anchors used to verify the
    # forwarded client certificate.  Falls back to ca_path when empty.
    pca_trust_anchors: list[Path] = []
    # Source addresses (ASGI scope client hosts) the client-cert header is
    # accepted from.  Empty = accept from any source (network must enforce
    # that only the proxy can reach this process).
    trusted_proxies: list[str] = []

    @model_validator(mode="after")
    def validate_proxy_terminated_tls(self) -> "TLSSettings":
        if self.proxy_terminated_tls:
            if not self.client_cert_header:
                raise ValueError(
                    "proxy_terminated_tls requires client_cert_header "
                    "(the header the trusted proxy injects, e.g. 'X-SSL-Client-Cert')"
                )
            if not self.pca_trust_anchors and self.ca_path is None:
                raise ValueError(
                    "proxy_terminated_tls requires pca_trust_anchors (or ca_path) "
                    "so the forwarded client certificate can be verified (§5.4)"
                )
        return self


class CoreSettings(BaseModel):
    """Runtime settings for i3-fe-core.

    Instantiate directly or build from a dict / environment dict resolved by
    the FE.  Example::

        settings = CoreSettings(
            log_level="DEBUG",
            ntp_servers=["ntp1.example.com", "ntp2.example.com"],
            tls=TLSSettings(mode=TLSMode.MTLS, cert_path=..., key_path=..., ca_path=...),
            logging_service_uri="https://logger.example.com",
        )
    """

    log_level: str = "INFO"
    ntp_servers: list[str] = ["pool.ntp.org"]
    tls: TLSSettings = TLSSettings()
    # URI of the i3 Logging Service this element ships events to (§4.12).
    logging_service_uri: str | None = None

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid:
            raise ValueError(f"log_level must be one of {valid}")
        return upper

    @field_validator("ntp_servers")
    @classmethod
    def validate_ntp_servers(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("ntp_servers must contain at least one server")
        return v

    @classmethod
    def from_dict(cls, data: dict) -> "CoreSettings":
        """Convenience: build CoreSettings from a plain dict."""
        return cls.model_validate(data)
