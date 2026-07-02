"""Tests for time/ntp.py — §2.2 NTP requirements.

NTP tests avoid hitting real servers by patching the blocking _query method.
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import patch, MagicMock

import pytest

from i3_fe_core.time.ntp import (
    ESINET_DRIFT_THRESHOLD_S,
    NtpClient,
    NtpSample,
)


def _make_sample(offset: float = 0.0, delay: float = 0.001, stratum: int = 2) -> NtpSample:
    return NtpSample(offset=offset, delay=delay, stratum=stratum, ref_mono=time.monotonic())


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

def test_no_servers_raises():
    with pytest.raises(ValueError):
        NtpClient(servers=[])


def test_initial_state():
    client = NtpClient(servers=["pool.ntp.org"])
    assert client.offset is None
    assert client.last_sync_age is None
    assert client.is_healthy is False


# ---------------------------------------------------------------------------
# After a successful sync
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_start_populates_sample():
    client = NtpClient(servers=["fake.ntp"])
    with patch.object(client, "_query", return_value=_make_sample(0.002)):
        await client.start()
        await client.stop()

    assert client.offset == pytest.approx(0.002)
    assert client.last_sync_age is not None
    assert client.last_sync_age >= 0.0


@pytest.mark.asyncio
async def test_is_healthy_within_threshold():
    client = NtpClient(servers=["fake.ntp"], drift_threshold=0.1)
    with patch.object(client, "_query", return_value=_make_sample(0.05)):
        await client.start()
        await client.stop()

    assert client.is_healthy is True


@pytest.mark.asyncio
async def test_is_unhealthy_outside_threshold():
    client = NtpClient(servers=["fake.ntp"], drift_threshold=0.1)
    with patch.object(client, "_query", return_value=_make_sample(0.15)):
        await client.start()
        await client.stop()

    assert client.is_healthy is False


# ---------------------------------------------------------------------------
# Fallback to next server on failure
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_falls_back_to_second_server():
    client = NtpClient(servers=["bad.ntp", "good.ntp"])
    call_count = 0

    def fake_query(server: str) -> NtpSample:
        nonlocal call_count
        call_count += 1
        if server == "bad.ntp":
            raise OSError("connection refused")
        return _make_sample(0.001)

    with patch.object(client, "_query", side_effect=fake_query):
        await client.start()
        await client.stop()

    assert client.offset == pytest.approx(0.001)
    assert call_count == 2  # tried bad first, then good


# ---------------------------------------------------------------------------
# Drift threshold constant matches the standard
# ---------------------------------------------------------------------------

def test_drift_threshold_is_point_one():
    """§2.2: absolute time difference ≤ 0.1 s across elements."""
    assert ESINET_DRIFT_THRESHOLD_S == pytest.approx(0.1)


# ---------------------------------------------------------------------------
# HardwareClockSource protocol hook
# ---------------------------------------------------------------------------

def test_hardware_clock_hook_accepted():
    class FakeHWClock:
        def get_time(self) -> float:
            return time.time()

    client = NtpClient(servers=["pool.ntp.org"], hw_clock=FakeHWClock())
    # Simply verify the constructor accepts the hook without raising.
    assert client is not None
