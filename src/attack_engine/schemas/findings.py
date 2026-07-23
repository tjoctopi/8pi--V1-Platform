"""Finding, Asset, and Service schemas — the nodes of the knowledge store.

The finding lifecycle encodes rule #1 (propose vs. verify):

    PROPOSED  -> an agent/tool suggested it. Carries no authority.
    VERIFIED  -> a deterministic oracle re-checked the raw evidence.
    CONFIRMED -> verified *and* correlated (reachability + scoring) — the only
                 state a report or gate may act on.
    REJECTED  -> an oracle disproved it (kept for audit / false-positive study).

State only moves forward along PROPOSED -> VERIFIED -> CONFIRMED, or sideways
to REJECTED. The transition is guarded in code (:meth:`Finding.promote`) so a
model can never write ``state="confirmed"`` directly.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import Field, model_validator

from .common import StrictModel, new_id, utcnow

#: Finding-type prefixes that denote an actual vulnerability (as opposed to a
#: mere observation such as an exposed service or a discovered web path). Used
#: by the Verifier to score and by the correlator to finalise into CONFIRMED.
VULN_TYPE_PREFIXES = (
    "sqli", "xss", "rce", "path-traversal", "ssrf", "lfi", "xxe",
    "command-injection", "cmdi", "ssti", "template-injection", "default-cred",
    "open-redirect",
)


class FindingState(str, Enum):
    PROPOSED = "proposed"
    VERIFIED = "verified"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class Priority(str, Enum):
    PATCH_IMMEDIATELY = "patch_immediately"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


#: Allowed forward transitions. REJECTED is terminal; CONFIRMED is terminal.
_ALLOWED_TRANSITIONS: dict[FindingState, frozenset[FindingState]] = {
    FindingState.PROPOSED: frozenset({FindingState.VERIFIED, FindingState.REJECTED}),
    FindingState.VERIFIED: frozenset({FindingState.CONFIRMED, FindingState.REJECTED}),
    FindingState.CONFIRMED: frozenset(),
    FindingState.REJECTED: frozenset(),
}


class Service(StrictModel):
    """A network service observed on an asset (e.g. ``Apache/2.4.49`` on :80)."""

    port: int = Field(ge=0, le=65535)
    protocol: str = Field(default="tcp", pattern=r"^(tcp|udp|sctp)$")
    name: str | None = None  # e.g. "http", "ssh"
    product: str | None = None  # e.g. "Apache httpd"
    version: str | None = None  # e.g. "2.4.49"
    banner: str | None = None

    @property
    def cpe_hint(self) -> str:
        """A coarse product/version string used by the correlator."""

        bits = [b for b in (self.product, self.version) if b]
        return "/".join(bits) if bits else (self.name or "unknown")


class Asset(StrictModel):
    """A host/endpoint in scope: the primary node type in the attack graph."""

    id: str = Field(default_factory=lambda: new_id("a"))
    address: str  # IP or hostname (validated against scope at ingest time)
    hostnames: tuple[str, ...] = Field(default_factory=tuple)
    services: tuple[Service, ...] = Field(default_factory=tuple)
    #: Reachable from the engagement entry node? Computed by the graph.
    reachable: bool = False
    engagement_id: str
    first_seen: str = Field(default_factory=lambda: utcnow().isoformat())


class Finding(StrictModel):
    """A potential security issue, moving through the propose/verify lifecycle."""

    id: str = Field(default_factory=lambda: new_id("f"))
    engagement_id: str
    asset: str  # asset address or id
    service: str | None = None  # e.g. "Apache/2.4.49"
    type: str  # e.g. "CVE-2021-41773" or "open-port" or "sqli-boolean-blind"
    title: str | None = None
    description: str | None = None

    state: FindingState = FindingState.PROPOSED
    verified_by: str | None = None  # oracle id/name that verified it
    rejected_reason: str | None = None

    reachable: bool = False
    on_kev: bool = False
    #: Calibrated Bayesian exploitability probability — NOT raw CVSS.
    exploit_prob: float | None = Field(default=None, ge=0.0, le=1.0)
    priority: Priority | None = None

    #: Pointers into the audit log / oracle outputs. Never inline raw bytes.
    evidence: tuple[str, ...] = Field(default_factory=tuple)
    proposed_by: str | None = None  # agent/tool that first surfaced it

    #: Structured detail the proposer attaches for downstream stages — e.g. an
    #: SQLi injection point (path/param/payloads) for the verification oracle,
    #: or a CVE id list for the correlator. Never holds raw bytes.
    metadata: dict[str, Any] = Field(default_factory=dict)

    created_at: str = Field(default_factory=lambda: utcnow().isoformat())
    updated_at: str = Field(default_factory=lambda: utcnow().isoformat())

    @model_validator(mode="after")
    def _state_invariants(self) -> Finding:
        if self.state is FindingState.CONFIRMED and self.verified_by is None:
            raise ValueError("a CONFIRMED finding must record verified_by")
        if self.state is FindingState.REJECTED and not self.rejected_reason:
            raise ValueError("a REJECTED finding must record rejected_reason")
        return self

    def can_transition_to(self, new_state: FindingState) -> bool:
        return new_state in _ALLOWED_TRANSITIONS[self.state]

    def promote(
        self,
        new_state: FindingState,
        *,
        verified_by: str | None = None,
        rejected_reason: str | None = None,
        evidence: tuple[str, ...] = (),
        exploit_prob: float | None = None,
        priority: Priority | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Finding:
        """Return a new Finding advanced to ``new_state``.

        Raises ``ValueError`` on an illegal transition. This is the *only*
        sanctioned way to change a finding's state — enforcing rule #1 in code.
        An optional calibrated ``exploit_prob`` / ``priority`` may be attached at
        promotion time (the Verifier/correlator scoring stages), and ``metadata``
        merges impact/remediation fields onto the finding (existing keys win, so a
        richer feed-provided value — e.g. a CVE's CVSS — is never clobbered).
        """

        if not self.can_transition_to(new_state):
            raise ValueError(
                f"illegal finding transition {self.state.value} -> {new_state.value}"
            )
        data = self.model_dump()
        data["state"] = new_state
        data["updated_at"] = utcnow().isoformat()
        if verified_by is not None:
            data["verified_by"] = verified_by
        if rejected_reason is not None:
            data["rejected_reason"] = rejected_reason
        if evidence:
            data["evidence"] = tuple(self.evidence) + tuple(evidence)
        if exploit_prob is not None:
            data["exploit_prob"] = exploit_prob
        if priority is not None:
            data["priority"] = priority
        if metadata:
            data["metadata"] = {**metadata, **(self.metadata or {})}
        return Finding.model_validate(data)
