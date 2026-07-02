"""state — ElementState, ServiceState, and the StateStore interface.

Covers: NENA-STA-010.3f-2021 §2.4.1 + §10.13 (ElementState),
        §2.4.2 + §10.12 + §10.18 (ServiceState).

Authoritative state is accessed through StateStore so that a future
multi-worker deployment can substitute a distributed backend without
changing FE code.
"""
