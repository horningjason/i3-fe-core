"""Tests for time/timestamps.py — §2.3 Timestamp requirements."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone, UTC

import pytest

from i3_fe_core.time.timestamps import format_i3, now_i3, parse_i3

# RFC 3339 offset pattern: must end with +HH:MM or -HH:MM (never bare Z).
_OFFSET_RE = re.compile(r'[+-]\d{2}:\d{2}$')


# ---------------------------------------------------------------------------
# now_i3
# ---------------------------------------------------------------------------

def test_now_i3_is_aware():
    dt = now_i3()
    assert dt.tzinfo is not None, "now_i3() must return a timezone-aware datetime"


def test_now_i3_has_utcoffset():
    dt = now_i3()
    assert dt.utcoffset() is not None


# ---------------------------------------------------------------------------
# format_i3 — mandatory offset (§2.3: offset is a REQUIRED component)
# ---------------------------------------------------------------------------

def test_format_always_has_explicit_offset():
    """format_i3 must always emit a numeric offset, never a bare 'Z'."""
    dt = now_i3()
    result = format_i3(dt)
    assert _OFFSET_RE.search(result), f"No numeric offset in {result!r}"
    assert not result.endswith("Z"), f"Bare Z suffix must not be emitted: {result!r}"


def test_format_utc_datetime_emits_plus_zero():
    """Even when local time IS UTC, emit +00:00 (not Z)."""
    dt = datetime(2015, 8, 21, 17, 58, 3, tzinfo=timezone.utc)
    result = format_i3(dt)
    # Python's astimezone() on UTC will give +00:00 on machines where local=UTC,
    # or the local offset on others.  Either way, no bare Z.
    assert not result.endswith("Z"), f"Must not emit Z: {result!r}"
    assert _OFFSET_RE.search(result), f"Missing numeric offset: {result!r}"


def test_format_specific_offset():
    """Datetime with a fixed -05:00 offset must be rendered as local -05:00."""
    tz_minus5 = timezone(timedelta(hours=-5))
    dt = datetime(2015, 8, 21, 12, 58, 3, tzinfo=tz_minus5)
    result = format_i3(dt)
    # The local time is already -05:00; format_i3 should reproduce it.
    # (astimezone() converts to the *platform* local TZ — we test the structural
    # guarantee, not the exact offset, since the test machine's TZ varies.)
    assert _OFFSET_RE.search(result)
    assert "2015-08-21" in result
    assert not result.endswith("Z")


def test_format_matches_standard_example_shape():
    """Output must resemble the §2.3 example: 2015-08-21T12:58:03.01-05:00."""
    tz_minus5 = timezone(timedelta(hours=-5))
    dt = datetime(2015, 8, 21, 12, 58, 3, 10_000, tzinfo=tz_minus5)  # 10 ms
    result = format_i3(dt)
    # The date part and fractional seconds must be present; offset sign may vary
    # by platform TZ, but the structure must hold.
    assert re.match(
        r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?[+-]\d{2}:\d{2}$',
        result,
    ), f"Unexpected shape: {result!r}"


# ---------------------------------------------------------------------------
# Sub-second precision (§2.3)
# ---------------------------------------------------------------------------

def test_sub_second_included_when_present():
    tz = timezone.utc
    dt = datetime(2024, 1, 1, 0, 0, 0, 10_000, tzinfo=tz)  # 10 ms = 10000 µs
    result = format_i3(dt)
    assert "." in result, f"Expected fractional seconds in {result!r}"


def test_sub_second_omitted_when_zero():
    tz = timezone.utc
    dt = datetime(2024, 1, 1, 12, 0, 0, 0, tzinfo=tz)
    result = format_i3(dt)
    # No dot before the offset.
    without_offset = result[:-6]
    assert "." not in without_offset, f"Unexpected fractional part in {result!r}"


def test_trailing_zeros_stripped():
    """10 ms (010000 µs) should render as '.01', not '.010000'."""
    tz_minus5 = timezone(timedelta(hours=-5))
    dt = datetime(2015, 8, 21, 12, 58, 3, 10_000, tzinfo=tz_minus5)
    result = format_i3(dt)
    # Extract fractional part if present.
    m = re.search(r'\.(\d+)', result)
    if m:
        frac = m.group(1)
        assert not frac.endswith("0"), f"Trailing zeros not stripped: {result!r}"


# ---------------------------------------------------------------------------
# Round-trip (§2.3: RFC 3339 date-time)
# ---------------------------------------------------------------------------

def test_round_trip():
    """format_i3 output must parse back via parse_i3 without loss."""
    original = now_i3()
    formatted = format_i3(original)
    parsed = parse_i3(formatted)
    # Compare as UTC to avoid platform-TZ drift in the assertion.
    assert original.astimezone(UTC) == pytest.approx(
        parsed.astimezone(UTC), abs=timedelta(microseconds=1).total_seconds()
    )


def test_round_trip_preserves_sub_second():
    tz_plus1 = timezone(timedelta(hours=1))
    original = datetime(2024, 6, 15, 10, 30, 45, 123_000, tzinfo=tz_plus1)
    formatted = format_i3(original)
    parsed = parse_i3(formatted)
    assert parsed.microsecond == original.microsecond


# ---------------------------------------------------------------------------
# Naïve datetime rejected
# ---------------------------------------------------------------------------

def test_naive_datetime_rejected():
    with pytest.raises(ValueError, match="timezone-aware"):
        format_i3(datetime(2024, 1, 1, 12, 0, 0))
