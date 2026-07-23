"""Belief schemas — the attacker's probabilistic world model (spec §2, the brain).

A :class:`Hypothesis` is a *proposal-space* object: the fleet's belief that a
weakness may exist, carried with a confidence and full provenance. It is never
truth. Proving it is the deterministic oracle's job (rule #1), at which point it
graduates into a :class:`~attack_engine.schemas.findings.Finding` and runs the
propose→verify→confirm lifecycle. Confidence is updated by Bayesian fusion of
independent :class:`Observation` signals (see
:class:`~attack_engine.knowledge.worldmodel.WorldModel`), so agreeing signals
raise it and contradicting ones lower it — the way an operator's belief moves
as probes come back.
"""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from .common import StrictModel, new_id, utcnow


class HypothesisStatus(str, Enum):
    """Where a hypothesis sits in the fleet's *proposal-space* reasoning.

    Deliberately has no ``CONFIRMED`` value: confirmation is a Finding's word,
    earned from a deterministic oracle (rule #1). A hypothesis only ever ranges
    from an untested hunch to a well-supported lead — or dies as refuted.
    """

    OPEN = "open"  # an untested lead
    TESTING = "testing"  # actively being probed
    SUPPORTED = "supported"  # evidence has raised confidence (still not proof)
    REFUTED = "refuted"  # evidence (or an oracle) knocked it down


class Observation(StrictModel):
    """One independent signal bearing on a hypothesis — the unit of provenance.

    Maps directly onto the fusion layer's evidence model: ``probability`` is
    P(hypothesis true | this signal alone) and ``weight`` scales how much the
    source is trusted.
    """

    source: str  # tool/agent/oracle that produced the signal
    probability: float = Field(ge=0.0, le=1.0)
    weight: float = Field(default=1.0, ge=0.0)
    note: str = ""
    at: str = Field(default_factory=lambda: utcnow().isoformat())


class Hypothesis(StrictModel):
    """A believed-possible weakness the fleet reasons and acts upon.

    ``confidence`` is the fused posterior over :attr:`observations` given
    :attr:`prior`; the WorldModel recomputes it on every new observation. A fresh
    attacker hunch starts below 50/50 (default prior 0.3) — belief is earned.
    """

    id: str = Field(default_factory=lambda: new_id("h"))
    engagement_id: str
    subject: str  # asset address/id, or an endpoint URL, the hunch concerns
    kind: str  # e.g. "cve", "sqli", "idor", "weak-cred", "misconfig", "open-port"
    title: str
    rationale: str = ""

    status: HypothesisStatus = HypothesisStatus.OPEN
    prior: float = Field(default=0.3, ge=0.0, le=1.0)
    confidence: float = Field(default=0.3, ge=0.0, le=1.0)
    observations: tuple[Observation, ...] = Field(default_factory=tuple)

    #: Informational hints for the planner — tool names that *could* test this.
    #: Never executed from here; the Tool Runner boundary still governs any run.
    suggested_tools: tuple[str, ...] = Field(default_factory=tuple)

    #: Oracle metadata that the round-trippable :attr:`subject` URL cannot encode
    #: — e.g. a POST form's request method plus the fixed companion fields
    #: (``method``/``params``/``data``) an injection needs to submit. The subject
    #: stays the dedup key; this rides alongside and is merged into the graduated
    #: Finding's metadata. Empty for the common GET-query injection point.
    context: dict[str, object] = Field(default_factory=dict)

    created_by: str = "ideator"
    #: Set once the hypothesis graduates into a Finding (its truth now lives there).
    finding_id: str | None = None
    created_at: str = Field(default_factory=lambda: utcnow().isoformat())
    updated_at: str = Field(default_factory=lambda: utcnow().isoformat())

    @property
    def is_active(self) -> bool:
        """A live lead worth pursuing: not refuted and not yet a Finding."""

        return self.status is not HypothesisStatus.REFUTED and self.finding_id is None
