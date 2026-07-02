"""Tests for config/identity.py — §2.1 identity requirements."""

import pytest
from pydantic import ValidationError

from i3_fe_core.config.identity import ElementIdentity


# ---------------------------------------------------------------------------
# Valid construction
# ---------------------------------------------------------------------------

def test_minimal_valid():
    identity = ElementIdentity(
        element_id="esrp1.state.pa.us",
        agency_id="police.allegheny.pa.us",
    )
    assert identity.element_id == "esrp1.state.pa.us"
    assert identity.agency_id == "police.allegheny.pa.us"
    assert identity.agent_id is None
    assert identity.agent_address is None


def test_full_valid():
    identity = ElementIdentity(
        element_id="lvf1.psap.allegheny.pa.us",
        agency_id="psap.allegheny.pa.us",
        agent_id="tom.jones",
        service_id="lvf.psap.allegheny.pa.us",
        service_name="LVF",
    )
    assert identity.agent_address == "tom.jones@psap.allegheny.pa.us"


def test_trailing_dot_normalised():
    # §2.1.1: FQDN with and without trailing dot MUST be treated as equivalent.
    identity = ElementIdentity(
        element_id="esrp1.state.pa.us.",
        agency_id="police.allegheny.pa.us.",
    )
    assert not identity.element_id.endswith(".")
    assert not identity.agency_id.endswith(".")


def test_fqdn_case_normalised():
    # §2.1.1: FQDNs are case-insensitive — normalise to lowercase.
    identity = ElementIdentity(
        element_id="ESRP1.State.PA.US",
        agency_id="Police.Allegheny.PA.US",
    )
    assert identity.element_id == "esrp1.state.pa.us"
    assert identity.agency_id == "police.allegheny.pa.us"


def test_agent_id_dot_string_valid():
    identity = ElementIdentity(
        element_id="e.example.com",
        agency_id="example.com",
        agent_id="tjones.atroop",
    )
    assert identity.agent_id == "tjones.atroop"
    assert identity.agent_address == "tjones.atroop@example.com"


# ---------------------------------------------------------------------------
# Validation failures
# ---------------------------------------------------------------------------

def test_empty_element_id_rejected():
    with pytest.raises(ValidationError, match="must be non-empty"):
        ElementIdentity(element_id="", agency_id="example.com")


def test_empty_agency_id_rejected():
    with pytest.raises(ValidationError, match="must be non-empty"):
        ElementIdentity(element_id="e.example.com", agency_id="")


def test_single_label_rejected():
    # No dot → not an FQDN.
    with pytest.raises(ValidationError, match="fully-qualified"):
        ElementIdentity(element_id="localhost", agency_id="example.com")


def test_invalid_label_chars_rejected():
    with pytest.raises(ValidationError):
        ElementIdentity(element_id="e_.example.com", agency_id="example.com")


def test_agent_id_with_space_rejected():
    with pytest.raises(ValidationError, match="Dot-string"):
        ElementIdentity(
            element_id="e.example.com",
            agency_id="example.com",
            agent_id="tom jones",
        )


def test_service_id_must_be_fqdn():
    with pytest.raises(ValidationError):
        ElementIdentity(
            element_id="e.example.com",
            agency_id="example.com",
            service_id="notafqdn",
        )
