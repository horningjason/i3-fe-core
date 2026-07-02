"""conformance — pytest helpers for asserting i3 compliance.

Import ``assert_core_conformance`` for a single-call full suite, or individual
helpers for targeted checks in your FE's own test module.

Example::

    from i3_fe_core.conformance.checks import assert_core_conformance

    def test_my_fe_conformance():
        assert_core_conformance(my_app, my_identity)
"""

from i3_fe_core.conformance.checks import (
    assert_core_conformance,
    assert_element_state_notify_body,
    assert_element_state_registry,
    assert_log_event_prologue,
    assert_ntp_reporting,
    assert_security_posture_registry,
    assert_service_state_notify_body,
    assert_service_state_registry,
    assert_timestamp_has_offset,
)

__all__ = [
    "assert_core_conformance",
    "assert_element_state_notify_body",
    "assert_element_state_registry",
    "assert_log_event_prologue",
    "assert_ntp_reporting",
    "assert_security_posture_registry",
    "assert_service_state_notify_body",
    "assert_service_state_registry",
    "assert_timestamp_has_offset",
]
