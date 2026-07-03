"""Tests for gis/cache.py — DatasetCache mtime-keyed cache + watcher."""

import datetime
import json
import os

from i3_fe_core.gis.cache import DatasetCache


class FakeSpec:
    """Minimal DatasetSpec whose payload is a trivial dict round-trip."""

    def __init__(self, source_path: str) -> None:
        self._source_path = source_path
        self.populate_from_source_calls = 0
        self.populate_from_cache_calls = 0
        self.data: dict | None = None

    @property
    def source_path(self) -> str:
        return self._source_path

    @property
    def cache_key(self) -> str:
        return "fake"

    def populate_from_source(self, now: datetime.datetime) -> None:
        self.populate_from_source_calls += 1
        with open(self._source_path, encoding="utf-8") as f:
            content = f.read()
        self.data = {"content": content}

    def populate_from_cache(self, payload: dict, now: datetime.datetime) -> None:
        self.populate_from_cache_calls += 1
        self.data = payload

    def serialize(self) -> dict:
        return self.data


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def test_first_load_is_miss_and_writes_cache(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("hello")
    spec = FakeSpec(str(source))
    cache = DatasetCache(spec)

    cache.load(_now())

    assert spec.populate_from_source_calls == 1
    assert spec.populate_from_cache_calls == 0
    assert spec.data == {"content": "hello"}

    cache_path = str(tmp_path / "source.fake.cache.json")
    assert os.path.exists(cache_path)
    with open(cache_path, encoding="utf-8") as f:
        written = json.load(f)
    assert written["payload"] == {"content": "hello"}


def test_second_load_with_unchanged_mtime_is_hit(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("hello")
    spec = FakeSpec(str(source))
    cache = DatasetCache(spec)

    cache.load(_now())
    cache.load(_now())

    assert spec.populate_from_source_calls == 1
    assert spec.populate_from_cache_calls == 1
    assert spec.data == {"content": "hello"}


def test_load_after_mtime_bump_is_miss_again(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("hello")
    spec = FakeSpec(str(source))
    cache = DatasetCache(spec)

    cache.load(_now())

    new_mtime = os.path.getmtime(str(source)) + 10
    source.write_text("goodbye")
    os.utime(str(source), (new_mtime, new_mtime))

    cache.load(_now())

    assert spec.populate_from_source_calls == 2
    assert spec.populate_from_cache_calls == 0
    assert spec.data == {"content": "goodbye"}
