"""Async NTP client.

Covers: NENA-STA-010.3f-2021 §2.2.

Requirements:
  • Every element MUST implement NTP (RFC 5905).
  • Hardware clock access MUST be available in each ESInet/NGCS.
  • Absolute time difference between any two elements MUST be ≤ 0.1 s.

Design:
  • NtpClient polls one or more configured servers on a configurable interval.
  • Offset, last-sync age, and a boolean health flag are exposed so the app
    layer (or ServiceState logic) can flag a degraded state when drift exceeds
    the ±0.1 s ESInet threshold.
  • HardwareClockSource is an optional hook — implement the protocol if the
    platform provides a hardware reference clock; leave it None otherwise.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

import ntplib

_log = logging.getLogger(__name__)

# §2.2: absolute time difference between any two elements MUST be ≤ 0.1 s.
ESINET_DRIFT_THRESHOLD_S: float = 0.1


@dataclass(frozen=True)
class NtpSample:
    """Single NTP measurement."""

    offset: float   # seconds; positive = system clock is behind NTP
    delay: float    # round-trip delay in seconds
    stratum: int    # NTP stratum of the server (1 = hardware clock, 2 = common pool)
    ref_mono: float = 0.0  # time.monotonic() at moment of measurement

    @property
    def age(self) -> float:
        """Seconds since this sample was taken."""
        return time.monotonic() - self.ref_mono


@runtime_checkable
class HardwareClockSource(Protocol):
    """Optional hardware reference clock hook.

    Implement this protocol and pass an instance to NtpClient if the platform
    provides a GPS-disciplined or other hardware clock.
    """

    def get_time(self) -> float:
        """Return current time as a POSIX timestamp."""
        ...


class NtpClient:
    """Async NTP client that polls configured servers and tracks drift health.

    Usage::

        client = NtpClient(servers=["pool.ntp.org"])
        await client.start()   # initial sync + starts background loop
        ...
        offset = client.offset
        healthy = client.is_healthy
        ...
        await client.stop()
    """

    # RFC 5905 §7.2 recommends a minimum poll interval of 64 s for production.
    DEFAULT_POLL_INTERVAL: float = 64.0

    def __init__(
        self,
        servers: list[str],
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        drift_threshold: float = ESINET_DRIFT_THRESHOLD_S,
        hw_clock: HardwareClockSource | None = None,
    ) -> None:
        if not servers:
            raise ValueError("At least one NTP server must be configured (§2.2)")
        self._servers = list(servers)
        self._poll_interval = poll_interval
        self._drift_threshold = drift_threshold
        self._hw_clock = hw_clock
        self._last_sample: NtpSample | None = None
        self._task: asyncio.Task | None = None

    # ------------------------------------------------------------------
    # Public read-only properties
    # ------------------------------------------------------------------

    @property
    def offset(self) -> float | None:
        """Current measured offset in seconds, or None before first sync."""
        return self._last_sample.offset if self._last_sample else None

    @property
    def last_sync_age(self) -> float | None:
        """Seconds elapsed since the most recent successful NTP exchange."""
        return self._last_sample.age if self._last_sample else None

    @property
    def last_sample(self) -> NtpSample | None:
        """Full NTP sample (offset, delay, stratum, age)."""
        return self._last_sample

    @property
    def is_healthy(self) -> bool:
        """True when the most recent sync is fresh and drift is within ±0.1 s.

        "Fresh" is defined as younger than two poll intervals — if the
        background loop misses two consecutive polls something is wrong.
        """
        if self._last_sample is None:
            return False
        if self._last_sample.age > self._poll_interval * 2:
            return False
        return abs(self._last_sample.offset) <= self._drift_threshold

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Perform an initial sync, then start the background polling loop."""
        await self._sync_once()
        self._task = asyncio.create_task(self._poll_loop(), name="ntp-poll")

    async def stop(self) -> None:
        """Cancel the polling loop and wait for it to finish."""
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _poll_loop(self) -> None:
        while True:
            await asyncio.sleep(self._poll_interval)
            await self._sync_once()

    async def _sync_once(self) -> None:
        """Try each configured server in order; record the first success."""
        loop = asyncio.get_running_loop()
        for server in self._servers:
            try:
                sample = await loop.run_in_executor(None, self._query, server)
                self._last_sample = sample
                _log.debug(
                    "NTP sync OK: server=%s offset=%.4fs delay=%.4fs stratum=%d",
                    server,
                    sample.offset,
                    sample.delay,
                    sample.stratum,
                )
                return
            except Exception as exc:
                _log.warning("NTP query failed for %s: %s", server, exc)
        _log.error("All NTP servers failed; system clock may drift beyond ±0.1 s (§2.2)")

    def _query(self, server: str) -> NtpSample:
        """Blocking NTP query — called via run_in_executor."""
        client = ntplib.NTPClient()
        # Version 4 per RFC 5905 (§2.2).
        response = client.request(server, version=4)
        return NtpSample(
            offset=response.offset,
            delay=response.delay,
            stratum=response.stratum,
            ref_mono=time.monotonic(),
        )
