"""Remediation + re-test schemas (spec §3 steps 6–7).

The Converter turns a confirmed finding into a *proposed* control — a patch diff
or a ticket. It proposes; it never applies. Applying a change is a gated,
human-authorised action, and the loop then *re-tests*: it re-runs the exact
attack path against the remediated state to prove the fix holds, escalating with
evidence if the vulnerability persists.
"""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from .common import StrictModel, new_id, utcnow


class RemediationKind(str, Enum):
    PATCH = "patch"          # a proposed diff / version bump
    TICKET = "ticket"        # a tracked work item
    CONFIG = "config"        # a configuration change
    MITIGATION = "mitigation"  # a compensating control


class RemediationStatus(str, Enum):
    PROPOSED = "proposed"        # Converter output; nothing changed yet
    APPLIED = "applied"          # human-approved + applied (gated)
    VERIFIED_FIXED = "verified_fixed"  # re-test confirmed the fix holds
    PERSISTED = "persisted"      # re-test still found it → escalated


class Remediation(StrictModel):
    """A proposed control for a confirmed finding. Propose-only until gated."""

    id: str = Field(default_factory=lambda: new_id("rem"))
    engagement_id: str
    finding_id: str
    kind: RemediationKind
    title: str
    #: The proposed change — a unified diff, ticket body, or config snippet.
    content: str
    status: RemediationStatus = RemediationStatus.PROPOSED
    proposed_by: str = "converter"
    #: Set once a human approves + applies (records the approver/audit id).
    applied_by: str | None = None
    apply_audit_id: str | None = None
    created_at: str = Field(default_factory=lambda: utcnow().isoformat())
    updated_at: str = Field(default_factory=lambda: utcnow().isoformat())


class RetestResult(StrictModel):
    """Outcome of re-running the exact attack path after remediation."""

    finding_id: str
    remediation_id: str | None = None
    #: True when the vulnerability is no longer detectable (fix holds).
    fixed: bool
    detail: str = ""
    evidence: tuple[str, ...] = Field(default_factory=tuple)
    ts: str = Field(default_factory=lambda: utcnow().isoformat())
