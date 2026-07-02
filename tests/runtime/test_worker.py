"""Tests for runtime/worker.py."""

from i3_fe_core.runtime.worker import SingleWorkerContext, WorkerContext


def test_single_worker_is_leader():
    ctx = SingleWorkerContext()
    assert ctx.is_leader() is True


def test_single_worker_id_default():
    ctx = SingleWorkerContext()
    assert ctx.worker_id() == "worker-0"


def test_single_worker_custom_id():
    ctx = SingleWorkerContext(id="primary")
    assert ctx.worker_id() == "primary"


def test_single_worker_is_worker_context():
    ctx = SingleWorkerContext()
    assert isinstance(ctx, WorkerContext)
