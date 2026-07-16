"""Attack-chain schemas — the multi-step path from a weak link to real impact.

A lone "info" finding is a *link*, not a dead end (agent-fleet habit #3: think in
chains). An :class:`AttackChain` is the fleet's belief that a sequence of rungs —
e.g. open-redirect → SSRF → cloud-metadata → credential-access → foothold —
composes into a real compromise, tracked as a path in the world model so the
orchestrator can pursue it and watch it light up rung by rung as oracles confirm.

Like a :class:`~attack_engine.schemas.beliefs.Hypothesis`, a chain lives in
proposal-space: it is a *plan*, never proof. Each rung graduates to a Finding and
is confirmed by a deterministic oracle independently (rule #1); the chain is
"realised" only once every rung it depends on is confirmed.
"""

from __future__ import annotations

from pydantic import Field

from .common import StrictModel, new_id, utcnow


class ChainStep(StrictModel):
    """One rung of an attack chain."""

    order: int = Field(ge=0)
    kind: str  # vuln/technique class of this rung (e.g. "ssrf", "cloud-metadata")
    subject: str  # injection point / asset / resource this rung acts on
    rationale: str = ""
    #: Links into the belief/finding stores as the rung is pursued and proven.
    hypothesis_id: str | None = None
    finding_id: str | None = None
    confirmed: bool = False  # set once a deterministic oracle proved this rung


class AttackChain(StrictModel):
    """An ordered path of rungs the fleet believes composes into impact."""

    id: str = Field(default_factory=lambda: new_id("chain"))
    engagement_id: str
    objective: str  # plain-language goal, e.g. "web foothold via SSRF→metadata→creds"
    entry_subject: str  # the injection point the chain starts from (dedup key)
    steps: tuple[ChainStep, ...] = Field(default_factory=tuple)
    created_by: str = "web-chainer"
    created_at: str = Field(default_factory=lambda: utcnow().isoformat())
    updated_at: str = Field(default_factory=lambda: utcnow().isoformat())

    @property
    def depth(self) -> int:
        return len(self.steps)

    @property
    def confirmed_depth(self) -> int:
        """How far the chain is actually proven, from the entry, without gaps."""

        proven = 0
        for step in sorted(self.steps, key=lambda s: s.order):
            if not step.confirmed:
                break
            proven += 1
        return proven

    @property
    def is_realised(self) -> bool:
        """Every rung confirmed — the chain is proven end-to-end."""

        return bool(self.steps) and all(s.confirmed for s in self.steps)
