"""DatasetSpec — the seam an FE implements to plug into DatasetCache.

The cache engine treats an FE's loaded data as opaque; the spec owns all
knowledge of source format, layers, record types, and derivations.
"""

from __future__ import annotations

import datetime
from typing import Protocol, runtime_checkable


@runtime_checkable
class DatasetSpec(Protocol):
    """What an FE supplies so the engine can cache/reload its dataset."""

    @property
    def source_path(self) -> str:
        """Path to the source file (e.g. a .gpkg)."""
        ...

    @property
    def cache_key(self) -> str:
        """Short id (e.g. "lvf", "mcs") — namespaces the cache file."""
        ...

    def populate_from_source(self, now: datetime.datetime) -> None:
        """Read the source file, derive whatever state the FE needs, and
        store it internally."""
        ...

    def populate_from_cache(self, payload: dict, now: datetime.datetime) -> None:
        """Rebuild internal state from a previously cached payload."""
        ...

    def serialize(self) -> dict:
        """Return a JSON-able payload capturing internal state to cache.

        The engine wraps this payload in its own envelope (source_mtime);
        the spec need not include the mtime itself.
        """
        ...
