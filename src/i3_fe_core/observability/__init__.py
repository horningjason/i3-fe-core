"""observability — shared operational infrastructure for FEs exporting metrics.

This is NOT a NENA-STA-010.3f-2021 standard obligation; it is reused
plumbing for every FE that runs multi-worker and needs Prometheus metrics
aggregated correctly across those workers. Only the FE-agnostic
prometheus_client multiprocess plumbing lives here — metric definitions
(names, labels) are per-FE and stay out of core.
"""

from __future__ import annotations

from i3_fe_core.observability.metrics import (
    clear_multiproc_dir,
    ensure_multiproc_dir,
    mark_worker_dead,
    metrics_app,
)

__all__ = [
    "ensure_multiproc_dir",
    "clear_multiproc_dir",
    "mark_worker_dead",
    "metrics_app",
]
