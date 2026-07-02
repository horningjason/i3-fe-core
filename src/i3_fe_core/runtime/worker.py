"""Worker context and leader gate.

The core is single-worker by default but never assumes single-worker.  Process
singletons — NTP sync loop, state publisher — call is_leader() before acting.
Swapping SingleWorkerContext for a distributed leader-election implementation
(Redis-based, etcd, etc.) is the only change required to enable multi-worker
deployments.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class WorkerContext(ABC):
    """Abstract leader gate.

    Callers should not cache the return value of is_leader() across yield
    points — leadership can change between awaits in a multi-worker scenario.
    """

    @abstractmethod
    def is_leader(self) -> bool:
        """Return True if this worker currently holds the leader role."""
        ...

    @abstractmethod
    def worker_id(self) -> str:
        """Return a stable, human-readable identifier for this worker."""
        ...


class SingleWorkerContext(WorkerContext):
    """Default leader gate for single-process deployments.

    Always reports is_leader() == True.  Replace with a real distributed
    election context when moving to multi-worker gunicorn.
    """

    def __init__(self, id: str = "worker-0") -> None:
        self._id = id

    def is_leader(self) -> bool:
        return True

    def worker_id(self) -> str:
        return self._id
