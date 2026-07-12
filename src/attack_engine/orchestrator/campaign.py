"""Autonomous campaign runner — goal-directed offense within authorization (O1).

Given an **objective** (host + privilege) and an **adversary profile** (the TTPs
an actor uses), the runner drives the loop autonomously *inside the signed
authorization*: recon → confirm footholds → plan the kill chain → advance toward
the objective, re-planning as new footholds appear, gating only the high-impact
list. It is the "decision loop" the strategy calls for — state in, next step out.

Governance is intact: the adversary profile only *declares* what the actor would
do; the signed RoE (:mod:`attack_engine.governance.authorization`) decides what
is actually *allowed*. Anything the scope doesn't authorize still gates. Steps
whose execution needs capabilities not yet built (real exploitation / C2 / AD —
O2–O5) are reported as ``pending_capabilities`` rather than silently skipped.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..schemas.common import StrictModel
from .report import EngagementReport

if TYPE_CHECKING:
    from ..engine import Engagement

#: Kill-chain phases whose *execution* (not just planning) requires offensive
#: capabilities landing in later phases. Until then they are planned, not run.
_PENDING_CAPABILITY = {
    "privilege_escalation": "local priv-esc capability (O2 exploitation / O5 AD)",
    "lateral_movement": "C2 + lateral capability (O3 / O5)",
    "objective": "post-exploitation capability (O3 / O5)",
}


class Objective(StrictModel):
    """What the campaign is trying to reach."""

    host: str
    privilege: str = "root"

    def label(self) -> str:
        return f"{self.host}:{self.privilege}"


class AdversaryProfile(StrictModel):
    """A declarative TTP playbook — "emulate this actor".

    ``kill_chain`` is the ordered sequence of MITRE ATT&CK technique ids the actor
    walks (Recon → … → Impact) — the emulation plan. ``techniques`` is the set of
    *authorization tokens* (action names like ``exploit_confirm`` /
    ``post_exploitation`` and/or ATT&CK ids) the campaign wants the signed RoE to
    authorize. Whether they actually run autonomously is decided by the RoE, not
    by this profile.
    """

    id: str
    name: str
    description: str = ""
    #: Ordered ATT&CK technique ids the actor employs (the emulation kill chain).
    kill_chain: tuple[str, ...] = ()
    #: Authorization tokens (action names + ATT&CK ids) the actor needs granted.
    techniques: frozenset[str] = frozenset()
    autonomy_tier: int = 1


class CampaignResult(StrictModel):
    engagement_id: str
    objective: str
    profile: str
    reached: bool
    iterations: int
    autonomous_actions: int
    gated_actions: int
    confirmed_footholds: int
    pending_capabilities: list[str] = []
    unauthorized_techniques: list[str] = []
    audit_intact: bool = True
    report: EngagementReport | None = None

    def to_markdown(self) -> str:
        head = "REACHED" if self.reached else "NOT REACHED"
        lines = [
            f"# Campaign — objective {self.objective}",
            "",
            f"- Adversary profile: **{self.profile}**",
            f"- Objective: **{head}** in {self.iterations} iteration(s)",
            f"- Autonomous actions: {self.autonomous_actions}  ·  "
            f"gated actions: {self.gated_actions}",
            f"- Confirmed footholds: {self.confirmed_footholds}",
            f"- Audit chain: {'intact ✅' if self.audit_intact else 'BROKEN ❌'}",
            "",
        ]
        if self.unauthorized_techniques:
            lines += [
                "## ⚠ Profile techniques the signed RoE did NOT authorize",
                "(these gate to a human rather than running autonomously)",
                "",
                *[f"- `{t}`" for t in self.unauthorized_techniques],
                "",
            ]
        if self.report is not None and self.report.kill_chain is not None:
            lines += ["## Planned route to objective", "",
                      self.report.kill_chain.to_markdown(), ""]
        lines += ["## Pending capabilities (block full objective execution)", ""]
        if not self.pending_capabilities:
            lines.append("_None — every planned step is executable/confirmed._")
        else:
            lines += [f"- {p}" for p in self.pending_capabilities]
        return "\n".join(lines) + "\n"


class CampaignRunner:
    """Drives an objective-directed, autonomy-bounded campaign for one engagement."""

    #: Bound on re-planning passes (each pass re-scans; the loop stops early once
    #: the objective is reached or no new footholds appear).
    MAX_ITERATIONS = 3

    def __init__(self, engagement: Engagement, profile: AdversaryProfile) -> None:
        self._eng = engagement
        self._profile = profile

    def run(self, targets: list[str], objective: Objective) -> CampaignResult:
        from ..schemas.findings import FindingState, Priority

        eng = self._eng
        scope = eng.scope
        roe = scope.roe
        # The profile declares TTPs; the SIGNED RoE authorizes them. Surface any
        # the scope does not cover — they will gate rather than run autonomously.
        unauthorized = sorted(
            t for t in self._profile.techniques
            if t not in roe.authorized_techniques and t not in roe.high_impact_actions
        ) if roe.autonomy_tier >= 1 else sorted(self._profile.techniques)

        orch = eng.orchestrator()  
        report: EngagementReport | None = None
        iterations = 0
        prev_footholds = -1
        reached = False

        while iterations < self.MAX_ITERATIONS:
            iterations += 1
            result = orch.run(
                list(targets), goal=f"campaign:{self._profile.id}",
                objective=(objective.host, objective.privilege),
            )
            report = result.report
            kc = report.kill_chain
            footholds = sum(
                1 for f in eng.store.findings(FindingState.CONFIRMED)  
                if f.priority is not Priority.INFORMATIONAL
            )
            reached = kc is not None and kc.reachable and kc.fully_confirmed
            if reached or footholds == prev_footholds:
                break  # objective proven, or no new progress → converged
            prev_footholds = footholds

        # Honest capability accounting: planned-but-unconfirmed steps need
        # offensive capabilities we haven't built yet.
        pending: list[str] = []
        if report is not None and report.kill_chain is not None:
            for step in report.kill_chain.steps:
                if step.confirmed:
                    continue
                need = _PENDING_CAPABILITY.get(step.phase.value, "execution capability")
                pending.append(f"{step.phase.value} ({step.technique}): {step.name} — needs {need}")

        audit = eng.audit  
        entries = audit.entries(scope.engagement_id)
        autonomous = sum(1 for e in entries if e.action == "action.authorized")
        gated = sum(1 for e in entries if e.action == "gate.request")
        footholds = sum(
            1 for f in eng.store.findings(FindingState.CONFIRMED)  
            if f.priority is not Priority.INFORMATIONAL
        )

        return CampaignResult(
            engagement_id=scope.engagement_id,
            objective=objective.label(),
            profile=self._profile.name,
            reached=reached,
            iterations=iterations,
            autonomous_actions=autonomous,
            gated_actions=gated,
            confirmed_footholds=footholds,
            pending_capabilities=pending,
            unauthorized_techniques=unauthorized,
            audit_intact=audit.verify(),
            report=report,
        )
