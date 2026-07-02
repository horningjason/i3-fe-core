"""Tests for config/settings.py."""

import pytest
from pydantic import ValidationError

from i3_fe_core.config.settings import CoreSettings, TLSMode, TLSSettings


def test_defaults():
    s = CoreSettings()
    assert s.log_level == "INFO"
    assert s.ntp_servers == ["pool.ntp.org"]
    assert s.tls.mode == TLSMode.OFF
    assert s.logging_service_uri is None


def test_from_dict():
    s = CoreSettings.from_dict({
        "log_level": "debug",
        "ntp_servers": ["ntp1.example.com"],
        "tls": {"mode": "mtls"},
    })
    assert s.log_level == "DEBUG"   # normalised to uppercase
    assert s.tls.mode == TLSMode.MTLS


def test_invalid_log_level():
    with pytest.raises(ValidationError, match="log_level"):
        CoreSettings(log_level="VERBOSE")


def test_empty_ntp_servers_rejected():
    with pytest.raises(ValidationError):
        CoreSettings(ntp_servers=[])
