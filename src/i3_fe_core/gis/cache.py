"""DatasetCache — mtime-keyed JSON cache and hot-reload watcher.

Wraps a DatasetSpec so an FE's dataset is rebuilt only when its source file
changes, and can be hot-reloaded without a process restart.  The engine
never inspects the cached payload's contents — it is opaque to this module.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import threading
import time
from collections.abc import Callable
from typing import Any

from i3_fe_core.gis.dataset import DatasetSpec

_log = logging.getLogger(__name__)


class DatasetCache:
    """Mtime-keyed JSON cache + hot-reload watcher around a DatasetSpec."""

    def __init__(self, spec: DatasetSpec, *, poll_interval_seconds: int = 60) -> None:
        self._spec = spec
        self._poll_interval_seconds = poll_interval_seconds
        self._cache_path = os.path.splitext(spec.source_path)[0] + f".{spec.cache_key}.cache.json"
        self._reloading = False
        self._reloading_lock = threading.Lock()

    @property
    def is_reloading(self) -> bool:
        with self._reloading_lock:
            return self._reloading

    def _set_reloading(self, value: bool) -> None:
        with self._reloading_lock:
            self._reloading = value

    def load(self, now: datetime.datetime) -> None:
        """Load the dataset, from cache if valid, otherwise from source.

        On a cache hit, populates the spec from the cached payload.  On a
        miss (no cache file, unreadable, or stale mtime), rebuilds from the
        source and writes a fresh cache file.  Cache write failures are
        logged and swallowed — the in-memory data is already populated.
        """
        source_mtime = os.path.getmtime(self._spec.source_path)

        cached = self._read_cache()
        if cached is not None and cached.get("source_mtime") == source_mtime:
            self._spec.populate_from_cache(cached["payload"], now)
            _log.info("dataset cache hit: %s", self._cache_path)
            return

        self._spec.populate_from_source(now)
        self._write_cache(source_mtime)

    def _read_cache(self) -> dict[str, Any] | None:
        if not os.path.exists(self._cache_path):
            return None
        try:
            with open(self._cache_path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError) as exc:
            _log.warning("failed to read dataset cache %s: %s", self._cache_path, exc)
            return None

    def _write_cache(self, source_mtime: float) -> None:
        tmp_path = self._cache_path + ".tmp"
        data = {"source_mtime": source_mtime, "payload": self._spec.serialize()}
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp_path, self._cache_path)
        except OSError as exc:
            _log.warning("failed to write dataset cache %s: %s", self._cache_path, exc)
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    def watch(
        self,
        get_now: Callable[[], datetime.datetime],
        on_success: Callable[[], None] | None = None,
        on_failure: Callable[[Exception], None] | None = None,
    ) -> None:
        """Blocking loop: poll the source mtime and hot-reload on change.

        Intended to run in a daemon thread. Never raises — reload failures
        are reported via ``on_failure`` and the loop continues.
        """
        try:
            last_mtime = os.path.getmtime(self._spec.source_path)
        except OSError as exc:
            _log.warning(
                "dataset watcher exiting: cannot stat source %s: %s",
                self._spec.source_path, exc,
            )
            return

        while True:
            time.sleep(self._poll_interval_seconds)
            try:
                current_mtime = os.path.getmtime(self._spec.source_path)
            except OSError as exc:
                _log.warning("dataset watcher: cannot stat source %s: %s", self._spec.source_path, exc)
                continue

            if current_mtime <= last_mtime:
                continue

            self._set_reloading(True)
            try:
                self.load(get_now())
                last_mtime = current_mtime
                if on_success is not None:
                    on_success()
            except Exception as exc:
                _log.exception("dataset hot-reload failed for %s", self._spec.source_path)
                if on_failure is not None:
                    on_failure(exc)
            finally:
                self._set_reloading(False)
