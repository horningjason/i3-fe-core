"""State types and StateStore interface.

Covers: NENA-STA-010.3f-2021 §2.4.1 + §10.13 (ElementState),
        §2.4.2 + §10.12 + §10.18 (ServiceState).

Design contract
---------------
State is stored as ONE self-contained bundle per scope (element / service) so
that a future shared backend (Redis, Postgres, IPC file) can save/load it as a
single atomic blob — no torn multi-key reads.

The CONTAINER and startup defaults defined here are all the core defines:
  element:  state=Normal, reason=""
  service:  state=Normal, reason="", security_posture=None

Specific reason strings, the condition→state mappings, and whether
security_posture applies are determined by each FE's own build logic (§4.3.2.6
ECRF/LVF, §4.4 MCS, §4.5 GCS).  The core ships NO reason catalog.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum


# ---------------------------------------------------------------------------
# IANA-registered enumerations
# ---------------------------------------------------------------------------

class ElementState(str, Enum):
    """IANA 'elementState' registry — NENA-STA-010.3f-2021 §10.13.

    Canonical enum; also exported from state.element_state.
    """

    NORMAL = "Normal"
    SCHEDULED_MAINTENANCE = "ScheduledMaintenance"
    SERVICE_DISRUPTION = "ServiceDisruption"
    OVERLOADED = "Overloaded"
    GOING_DOWN = "GoingDown"
    DOWN = "Down"
    # Set locally by the subscriber when it cannot reach this element (§2.4.1).
    UNREACHABLE = "Unreachable"


class ServiceState(str, Enum):
    """IANA 'serviceState' registry — NENA-STA-010.3f-2021 §10.12.

    Canonical enum; also exported from state.service_state.
    10 values as of NENA-STA-010.3f-2021.
    """

    NORMAL = "Normal"
    # Applies to PSAPs only (§10.12 note).
    UNSTAFFED = "Unstaffed"
    # Maintenance — not accepting service requests.
    SCHEDULED_MAINTENANCE_DOWN = "ScheduledMaintenanceDown"
    # Maintenance — still responding, possibly reduced availability.
    SCHEDULED_MAINTENANCE_AVAILABLE = "ScheduledMaintenanceAvailable"
    MAJOR_INCIDENT_IN_PROGRESS = "MajorIncidentInProgress"
    PARTIAL = "Partial"
    OVERLOADED = "Overloaded"
    GOING_DOWN = "GoingDown"
    DOWN = "Down"
    # Set locally by the subscriber when it cannot contact the service (§2.4.2).
    UNREACHABLE = "Unreachable"


class SecurityPosture(str, Enum):
    """IANA 'securityPosture' registry — NENA-STA-010.3f-2021 §10.18.

    Canonical enum; also exported from state.service_state.
    """

    GREEN = "Green"
    YELLOW = "Yellow"
    ORANGE = "Orange"
    RED = "Red"


# ---------------------------------------------------------------------------
# State bundles — serialised as-is into NOTIFY JSON bodies (§2.4.1 / §2.4.2)
# ---------------------------------------------------------------------------

@dataclass
class SecurityPostureBundle:
    """Security-posture sub-object in ServiceState (§2.4.2, §10.18)."""

    posture: SecurityPosture
    # OPTIONAL per §2.4.2 table; empty string when no reason text is available.
    reason: str = ""


@dataclass
class ElementStateBundle:
    """ElementState NOTIFY body — Application/EmergencyCallData.ElementState+json (§2.4.1)."""

    state: ElementState = ElementState.NORMAL
    # OPTIONAL field per §2.4.1; empty string when no reason text is available.
    reason: str = ""


@dataclass
class ServiceStateBundle:
    """ServiceState NOTIFY body — Application/EmergencyCallData.ServiceState+json (§2.4.2)."""

    state: ServiceState = ServiceState.NORMAL
    # MANDATORY per §2.4.2 ("otherwise, empty") — MUST be str, never None.
    reason: str = ""
    # CONDITIONAL: present only when the FE opts into security-posture tracking.
    security_posture: SecurityPostureBundle | None = None


# ---------------------------------------------------------------------------
# StateStore interface + default in-process implementation
# ---------------------------------------------------------------------------

class StateStore(ABC):
    """Interface for reading and writing the FE's authoritative state bundles.

    The default InProcessStateStore is suitable for single-worker deployments.
    Replace with a shared-backend implementation (Redis, Postgres, mmap …) to
    keep all workers coherent under multi-worker gunicorn without changing any
    caller code.
    """

    @abstractmethod
    def get_element_state(self) -> ElementStateBundle:
        """Return the current ElementState bundle."""
        ...

    @abstractmethod
    def set_element_state(self, bundle: ElementStateBundle) -> None:
        """Atomically replace the current ElementState bundle."""
        ...

    @abstractmethod
    def get_service_state(self) -> ServiceStateBundle:
        """Return the current ServiceState bundle."""
        ...

    @abstractmethod
    def set_service_state(self, bundle: ServiceStateBundle) -> None:
        """Atomically replace the current ServiceState bundle."""
        ...


class InProcessStateStore(StateStore):
    """In-memory StateStore for single-worker deployments (the default)."""

    def __init__(self) -> None:
        self._element: ElementStateBundle = ElementStateBundle()
        self._service: ServiceStateBundle = ServiceStateBundle()

    def get_element_state(self) -> ElementStateBundle:
        return self._element

    def set_element_state(self, bundle: ElementStateBundle) -> None:
        self._element = bundle

    def get_service_state(self) -> ServiceStateBundle:
        return self._service

    def set_service_state(self, bundle: ServiceStateBundle) -> None:
        self._service = bundle
