"""FE identity model.

Covers: NENA-STA-010.3f-2021 §2.1.1 (AgencyId), §2.1.2 (AgentId), §2.1.3 (ElementId).
"""

from __future__ import annotations

import re

from pydantic import BaseModel, field_validator, model_validator

# RFC 2664 / RFC 1123 hostname label rules.
# Label: 1-63 chars, alphanumeric + internal hyphens, not starting/ending with hyphen.
# FQDN: one or more dot-separated labels; optional trailing dot (§2.1.1).
_LABEL_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$')


def _validate_fqdn(value: str, field: str) -> str:
    """Validate and normalise an FQDN per §2.1.1/§2.1.3."""
    v = value.strip().rstrip(".")  # trailing dot is equivalent per §2.1.1
    if not v:
        raise ValueError(f"{field} must be non-empty")
    labels = v.split(".")
    if len(labels) < 2:
        raise ValueError(f"{field} must be a fully-qualified domain name (at least two labels)")
    for label in labels:
        if not label:
            raise ValueError(f"{field}: empty label in FQDN")
        if not _LABEL_RE.match(label):
            raise ValueError(
                f"{field}: label {label!r} is invalid — RFC 2664 allows "
                "alphanumeric and internal hyphens only"
            )
    if len(v) > 253:
        raise ValueError(f"{field}: FQDN exceeds 253 characters")
    return v.lower()  # §2.1.1: case-insensitive — normalise to lowercase


# RFC 5321 §4.1.2 Dot-string: printable characters except space/special, dot-separated.
# This is the "user part of an email address, without Quoted-String".
_DOT_STRING_RE = re.compile(
    r'^[a-zA-Z0-9!#$%&\'*+/=?^_`{|}~-]+'
    r'(\.[a-zA-Z0-9!#$%&\'*+/=?^_`{|}~-]+)*$'
)


class ElementIdentity(BaseModel):
    """Identity bundle for a single i3 Functional Element.

    element_id  — globally-unique FQDN of this element (§2.1.3)
    agency_id   — globally-unique FQDN of the owning Agency (§2.1.1)
    agent_id    — RFC 5321 Dot-string username, unique within agency_id (§2.1.2)
    service_id  — FQDN of the Service this element belongs to (§2.1.5)
    service_name — IANA serviceNames registry token (§10.11), e.g. "LVF", "MCS"
    """

    element_id: str
    agency_id: str
    agent_id: str | None = None
    service_id: str | None = None
    # IANA serviceNames registry §10.11 — validated as free string; callers should
    # use one of the registered tokens (ADR/Bridge/ECRF/ESRP/GCS/IMR/Logging/
    # LVF/MCS/MDS/PolicyStore/PSAP/SAL).
    service_name: str | None = None

    @field_validator("element_id")
    @classmethod
    def validate_element_id(cls, v: str) -> str:
        return _validate_fqdn(v, "element_id")

    @field_validator("agency_id")
    @classmethod
    def validate_agency_id(cls, v: str) -> str:
        return _validate_fqdn(v, "agency_id")

    @field_validator("agent_id")
    @classmethod
    def validate_agent_id(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not _DOT_STRING_RE.match(v):
            raise ValueError(
                f"agent_id {v!r} is not a valid RFC 5321 Dot-string "
                "(the user part of an email address, no Quoted-String)"
            )
        return v

    @field_validator("service_id")
    @classmethod
    def validate_service_id(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _validate_fqdn(v, "service_id")

    @property
    def agent_address(self) -> str | None:
        """Globally-unique agent address: agent_id@agency_id (§2.1.2)."""
        if self.agent_id is None:
            return None
        return f"{self.agent_id}@{self.agency_id}"
