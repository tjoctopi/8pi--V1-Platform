"""Autonomous adversary campaign (Phase F) — the whole kill chain, unattended.

Where the legacy :class:`~attack_engine.orchestrator.campaign.CampaignRunner`
drove the fixed 8-phase DAG and reported lateral / privesc / objective as
*pending capabilities*, this drives the **real** Phase A–E cognition end to end:
the recon, web, and identity specialists — each an objective-directed reasoning
loop — chained by the :class:`~attack_engine.orchestrator.controller.ObjectiveController`,
with **frontier expansion** between rounds (recon finds hosts, the web specialist
lands footholds, the identity specialist cracks/owns principals; each new vantage
grows the owned set and is re-planned from) until the campaign **goal** — by
default reaching Domain Admin — is met, the operator trips the kill switch, the
token budget runs out, or the frontier stops growing (convergence).

Governance is unchanged and always on: the campaign only *sequences* specialists;
every action still flows through the signed scope, the RoE authorization / human
gate, the hash-chained audit, and the kill switch (checked before every round and
phase). The adversary **profile** merely *declares* which TTPs an actor would use;
the signed RoE decides what actually runs autonomously versus gates. Propose-vs-
confirm holds throughout — specialists propose; oracles and deterministic checks
confirm (rule #1).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..agents.reasoning import ReasoningLoop
from ..gateway.budget import TokenBudget
from ..governance.audit import AuditLog
from ..governance.authorization import KillSwitch
from ..knowledge.worldmodel import WorldModel
from ..logging import get_logger
from ..schemas.common import StrictModel
from ..schemas.scope import Scope
from .controller import ObjectiveController
from .objective import DomainAdminObjective, Objective

if TYPE_CHECKING:
    from ..engine import Engagement
    from .campaign import AdversaryProfile

_log = get_logger("orchestrator.adversary")


@dataclass
class CampaignPhase:
    """One specialist on the campaign: its objective-directed reasoning loop."""

    name: str
    loop: ReasoningLoop
    objective: Objective


class PhaseRun(StrictModel):
    """The record of pursuing one phase in one round."""

    round: int
    name: str
    objective: str
    met: bool
    stop_reason: str
    iterations: int


class CampaignOutcome(StrictModel):
    """The result of an autonomous adversary campaign."""

    engagement_id: str
    profile: str
    goal: str
    goal_reached: bool
    rounds: int
    stop_reason: str
    phases: list[PhaseRun] = []
    #: The owned principals (identity frontier) at campaign end.
    owned_frontier: list[str] = []
    #: In-scope hosts reachable at campaign end (network frontier).
    reachable_hosts: int = 0
    autonomous_actions: int = 0
    gated_actions: int = 0
    audit_intact: bool = True

    def to_markdown(self) -> str:
        head = "REACHED" if self.goal_reached else "NOT REACHED"
        lines = [
            f"# Adversary campaign — {self.profile}",
            "",
            f"- Goal: **{self.goal}** — **{head}** ({self.stop_reason})",
            f"- Rounds: {self.rounds}",
            f"- Autonomous actions: {self.autonomous_actions}  ·  "
            f"gated: {self.gated_actions}",
            f"- Frontier: {self.reachable_hosts} reachable host(s), "
            f"{len(self.owned_frontier)} owned principal(s)",
            f"- Audit chain: {'intact ✅' if self.audit_intact else 'BROKEN ❌'}",
            "",
            "## Phases pursued",
            "",
        ]
        if not self.phases:
            lines.append("_No phases ran._")
        for p in self.phases:
            mark = "✅" if p.met else "◻"
            lines.append(
                f"- r{p.round} **{p.name}** {mark} — {p.stop_reason} "
                f"({p.iterations} step(s)): {p.objective}"
            )
        if self.owned_frontier:
            lines += ["", "## Owned principals", "",
                      *[f"- `{o}`" for o in self.owned_frontier]]
        return "\n".join(lines) + "\n"


@dataclass
class AdversaryCampaign:
    """Drives specialists toward a goal, expanding the frontier each round."""

    scope: Scope
    world_model: WorldModel
    audit: AuditLog
    phases: list[CampaignPhase]
    goal: Objective
    kill_switch: KillSwitch | None = None
    budget: TokenBudget | None = None
    max_rounds: int = 4
    profile_name: str = "custom"
    actor: str = "campaign"
    _runs: list[PhaseRun] = field(default_factory=list, init=False)

    def run(self) -> CampaignOutcome:
        """Pursue the goal round by round until met / halted / converged."""

        self.audit.append(
            engagement_id=self.scope.engagement_id, actor=self.actor,
            action="campaign.start", target=self.scope.engagement_id,
            payload={"goal": self.goal.describe(), "profile": self.profile_name,
                     "phases": [p.name for p in self.phases], "max_rounds": self.max_rounds},
        )

        if self.goal.is_satisfied(self.world_model):
            return self._complete(True, 0, "already_satisfied")

        stop_reason = "converged"
        rounds = 0
        for round_no in range(1, self.max_rounds + 1):
            if self._killed():
                stop_reason = "kill_switch"
                break
            if self._budget_exhausted():
                stop_reason = "budget_exhausted"
                break
            rounds = round_no
            frontier_before = self._frontier()
            self._run_round(round_no)
            if self.goal.is_satisfied(self.world_model):
                stop_reason = "objective_reached"
                break
            if self._killed():
                stop_reason = "kill_switch"
                break
            if self._frontier() == frontier_before:
                stop_reason = "converged"  # no new ground gained → nothing left to try
                break

        return self._complete(self.goal.is_satisfied(self.world_model), rounds, stop_reason)

    def _complete(self, goal_reached: bool, rounds: int, stop_reason: str) -> CampaignOutcome:
        self.audit.append(
            engagement_id=self.scope.engagement_id, actor=self.actor,
            action="campaign.complete", target=self.scope.engagement_id,
            payload={"goal_reached": goal_reached, "rounds": rounds,
                     "stop_reason": stop_reason},
        )
        return self._finalize(goal_reached, rounds, stop_reason)

    # --- internals ------------------------------------------------------------

    def _run_round(self, round_no: int) -> None:
        for phase in self.phases:
            if self.goal.is_satisfied(self.world_model):
                return  # goal met mid-round — no need to run later specialists
            if self._killed() or self._budget_exhausted():
                return
            result = ObjectiveController(phase.loop).pursue(
                self.world_model, phase.objective, budget=self.budget
            )
            self._runs.append(PhaseRun(
                round=round_no, name=phase.name, objective=phase.objective.describe(),
                met=result.objective_met, stop_reason=result.stop_reason,
                iterations=result.iterations,
            ))
            _log.info("campaign phase complete", round=round_no, phase=phase.name,
                      met=result.objective_met, stop_reason=result.stop_reason)

    def _frontier(self) -> int:
        """Ground gained so far: reachable hosts + owned principals. Growth between
        rounds is what makes another round worthwhile; no growth ⇒ converged."""

        return len(self.world_model.reachable_assets()) + len(
            self.world_model.owned_principals
        )

    def _killed(self) -> bool:
        return self.kill_switch is not None and self.kill_switch.tripped

    def _budget_exhausted(self) -> bool:
        if self.budget is None:
            return False
        remaining = self.budget.remaining()
        return remaining is not None and remaining <= 0

    def _finalize(self, goal_reached: bool, rounds: int, stop_reason: str) -> CampaignOutcome:
        entries = self.audit.entries(self.scope.engagement_id)
        autonomous = sum(1 for e in entries if e.action == "action.authorized")
        gated = sum(1 for e in entries if e.action == "gate.request")
        return CampaignOutcome(
            engagement_id=self.scope.engagement_id,
            profile=self.profile_name,
            goal=self.goal.describe(),
            goal_reached=goal_reached,
            rounds=rounds,
            stop_reason=stop_reason,
            phases=list(self._runs),
            owned_frontier=self.world_model.owned_principals,
            reachable_hosts=len(self.world_model.reachable_assets()),
            autonomous_actions=autonomous,
            gated_actions=gated,
            audit_intact=self.audit.verify(),
        )

    # --- construction from a live engagement ----------------------------------

    @classmethod
    def from_engagement(
        cls,
        engagement: Engagement,
        *,
        targets: list[str],
        profile: AdversaryProfile | None = None,
        goal: Objective | None = None,
        world_model: WorldModel | None = None,
        budget: TokenBudget | None = None,
        max_rounds: int = 4,
    ) -> AdversaryCampaign:
        """Wire a campaign over the engagement's real specialists.

        Seeds ``targets`` as reachable assets (so every specialist's planner sees
        the initial frontier), builds the recon → web → identity specialist loops
        from the engagement's :class:`~attack_engine.agents.context.AgentContext`,
        and pursues ``goal`` (default: reach Domain Admin) — the external→DA gate.
        """

        from ..agents.identity_specialist import build_identity_loop
        from ..agents.recon_specialist import build_recon_loop
        from ..agents.web_specialist import build_web_loop
        from .objective import ConfidenceObjective, MapSurfaceObjective

        wm = world_model or WorldModel(
            engagement.scope.engagement_id, store=engagement.store
        )
        seed_targets(engagement, targets)
        ctx = engagement.context
        phases = [
            CampaignPhase("recon", build_recon_loop(ctx),
                          MapSurfaceObjective(min_assets=1, min_hypotheses=1)),
            CampaignPhase("web", build_web_loop(ctx),
                          ConfidenceObjective(kind="vulnerability", threshold=0.85)),
            CampaignPhase("identity", build_identity_loop(ctx), DomainAdminObjective()),
        ]
        return cls(
            scope=engagement.scope, world_model=wm, audit=engagement.audit,
            phases=phases, goal=goal or DomainAdminObjective(),
            kill_switch=engagement.kill_switch, budget=budget, max_rounds=max_rounds,
            profile_name=profile.name if profile else "custom",
        )


def seed_targets(engagement: Engagement, targets: list[str]) -> None:
    """Register the initial in-scope targets as reachable assets on the engagement.

    Gives the campaign a starting network frontier the specialists' planners can
    act on. Out-of-scope targets are skipped (the store validates at ingest).
    """

    from ..schemas.findings import Asset

    for address in targets:
        try:
            engagement.store.add_asset(
                Asset(address=address, engagement_id=engagement.scope.engagement_id),
                emitted_by="campaign.seed", reachable_from_entry=True,
            )
        except Exception as exc:  # out-of-scope / invalid address — skip, don't abort
            _log.warning("skipped seeding target", address=address, error=str(exc))
