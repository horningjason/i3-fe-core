"""Tests for observability/metrics.py — prometheus multiprocess plumbing."""

import os

from i3_fe_core.observability.metrics import clear_multiproc_dir, ensure_multiproc_dir


def test_ensure_multiproc_dir_creates_dir_and_sets_env(tmp_path, monkeypatch):
    monkeypatch.delenv("PROMETHEUS_MULTIPROC_DIR", raising=False)
    target = tmp_path / "multiproc"

    ensure_multiproc_dir(str(target))

    assert os.environ["PROMETHEUS_MULTIPROC_DIR"] == str(target)
    assert os.path.isdir(target)


def test_ensure_multiproc_dir_does_not_override_existing_env(tmp_path, monkeypatch):
    existing = tmp_path / "existing"
    existing.mkdir()
    monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", str(existing))
    other_default = tmp_path / "other"

    ensure_multiproc_dir(str(other_default))

    assert os.environ["PROMETHEUS_MULTIPROC_DIR"] == str(existing)
    assert not os.path.isdir(other_default)


def test_clear_multiproc_dir_wipes_contents_and_recreates(tmp_path, monkeypatch):
    target = tmp_path / "multiproc"
    target.mkdir()
    stray_file = target / "counter_1234.db"
    stray_file.write_text("stale metric data")
    monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", str(target))

    clear_multiproc_dir()

    assert os.path.isdir(target)
    assert not stray_file.exists()
    assert list(target.iterdir()) == []


def test_clear_multiproc_dir_is_idempotent_when_dir_missing(tmp_path, monkeypatch):
    target = tmp_path / "does_not_exist_yet"
    monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", str(target))

    clear_multiproc_dir()
    clear_multiproc_dir()

    assert os.path.isdir(target)
