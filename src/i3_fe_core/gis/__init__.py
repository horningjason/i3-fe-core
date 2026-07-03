"""gis — shared operational infrastructure for FEs that load external datasets.

This is NOT a NENA-STA-010.3f-2021 standard obligation; it is reused
plumbing for every FE that loads GIS or other file-backed data:
``DatasetCache`` caches an opaque payload keyed by a source file's mtime,
rebuilds only when the source changes, and hot-reloads live without a
restart.  ``DatasetSpec`` is the seam an FE implements to plug its own
source format and derived state into the cache engine.
"""

from __future__ import annotations

from i3_fe_core.gis.cache import DatasetCache
from i3_fe_core.gis.dataset import DatasetSpec

__all__ = ["DatasetSpec", "DatasetCache"]
