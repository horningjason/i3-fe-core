"""FE-agnostic prometheus_client multiprocess plumbing.

Multi-worker correctness: plain prometheus_client does NOT aggregate across
gunicorn workers by default — each worker keeps separate in-memory counters,
so a single scrape would only reflect whichever worker happened to handle it.
prometheus_client's documented multiprocess mode fixes this: metrics are
backed by per-process mmap files under PROMETHEUS_MULTIPROC_DIR, and
/metrics is served from a dedicated CollectorRegistry + MultiProcessCollector
that aggregates across every worker's files at scrape time. See
https://prometheus.github.io/client_python/multiprocess/.

``ensure_multiproc_dir`` MUST be called by the FE BEFORE prometheus_client is
first imported anywhere in the process — multiprocess vs single-process mode
is decided once, at prometheus_client.values import time
(prometheus_client/values.py: ``ValueClass = get_value_class()``), by
checking os.environ at that moment. Setting the env var later is too late.
For that reason this module never imports prometheus_client at module level;
``mark_worker_dead`` and ``metrics_app`` below import it lazily, so that
merely importing this module (to reach ``ensure_multiproc_dir``) can never
itself be the first prometheus_client import in the process. The FE's own
metric-definition module should call ``ensure_multiproc_dir`` first, then
import prometheus_client to define its Counters/Histograms.

This module holds only the plumbing — no metric definitions. Metric names
and labels are per-FE and stay out of core.
"""

from __future__ import annotations

import os
import shutil


def ensure_multiproc_dir(default_dir: str) -> None:
    """Set PROMETHEUS_MULTIPROC_DIR (if unset) and ensure it exists.

    Must be called by the FE before prometheus_client is imported anywhere
    in the process — see module docstring. ``default_dir`` is the FE's own
    default; core does not hardcode one.
    """
    os.environ.setdefault("PROMETHEUS_MULTIPROC_DIR", default_dir)
    os.makedirs(os.environ["PROMETHEUS_MULTIPROC_DIR"], exist_ok=True)


def clear_multiproc_dir() -> None:
    """Wipe and recreate PROMETHEUS_MULTIPROC_DIR.

    Must be called exactly once, before any worker process starts (per the
    official multiprocess-mode guidance: the directory must be cleared
    between runs). Call this from the FE's prewarm/main entrypoint or
    gunicorn's on_starting hook — all of which run before workers fork or
    before the (single) dev process starts serving. Never call this from
    code that runs per-worker: a sibling worker's in-flight metric files
    could be deleted out from under it.

    ``ignore_errors=True`` is deliberate: on Windows an in-flight worker can
    still hold one of the .db files open, which would otherwise raise here.
    """
    path = os.environ["PROMETHEUS_MULTIPROC_DIR"]
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path, exist_ok=True)


def mark_worker_dead(pid: int) -> None:
    """Per the official gunicorn child_exit hook pattern — removes a dead
    worker's "live" gauge files so they don't skew livesum/liveall
    aggregation. A no-op for FEs that only use Counter/Histogram metrics
    (their per-pid files are cumulative and correctly retained), kept here
    so the standard hook is in place if a Gauge is ever added."""
    from prometheus_client import multiprocess

    multiprocess.mark_process_dead(pid)


def metrics_app():
    """Build the multiprocess-aware ASGI app to mount at GET /metrics.

    Per https://prometheus.github.io/client_python/exporting/http/fastapi-gunicorn/:
    a dedicated CollectorRegistry (NOT the default global registry that an
    FE's Counter/Histogram objects auto-register with) holds only a
    MultiProcessCollector, which reads and aggregates every worker's mmap
    files fresh on each scrape — so this single call is reused for the
    lifetime of the process; it is not rebuilt per-request.
    """
    from prometheus_client import CollectorRegistry, multiprocess
    from prometheus_client.asgi import make_asgi_app

    registry = CollectorRegistry(support_collectors_without_names=True)
    multiprocess.MultiProcessCollector(registry)
    return make_asgi_app(registry=registry)
