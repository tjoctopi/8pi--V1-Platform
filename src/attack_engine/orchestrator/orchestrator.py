"""Orchestrator — the Purple Commander (spec §3, §4, agent #1).

Owns the goal and scope, plans the attack DAG, dispatches the role agents in
dependency order, enforces gates, and closes the loop with a re-test. Agents
never call each other; the Orchestrator reads the blackboard and decides the
next dispatch, exactly as the architecture requires.

``run`` executes the autonomous, safe portion end to end (plan → recon → verify
→ web → confirm → correlate → convert → report). ``close_loop`` performs the
gated, real-world-effect portion — apply an approved remediation and re-test —
and escalates anything that persists. Applying a fix modifies a real system, so
it is deliberately *not* part of the autonomous ``run``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ..agents.archetypes.converter import Converter
from ..agents.context import AgentContext
from ..agents.loader import build_agent, load_specs
from ..defense.blue_sentry import BlueSentry
from ..intel.surface import build_attack_surface
from ..killchain.plan import KillChainPlan, KillChainPlanner
from ..knowledge.store import KnowledgeStore
from ..logging import get_logger
from ..netutil import web_targets
from ..schemas.agentspec import AgentSpec, Archetype
from ..schemas.events import Event, EventType
from ..schemas.findings import FindingState
from ..schemas.remediation import Remediation, RemediationStatus, RetestResult
from ..verify.context import VerifyContext
from .attackpath import build_attack_paths
from .plan import AttackPlan, Phase, build_plan
from .report import EngagementReport, build_report
from .retest import RetestRunner

if TYPE_CHECKING:
    from ..engine import Engagement

_log = get_logger("orchestrator")

_SPECS_DIR = Path(__file__).resolve().parent.parent / "agents" / "specs"


@dataclass
class LoopResult:
    plan: AttackPlan
    report: EngagementReport
    retests: list[RetestResult]


class Orchestrator:
    """Plans and drives the coordinated purple-team loop for one engagement."""

    def __init__(
        self,
        engagement: Engagement,
        *,
        specs: dict[Archetype, AgentSpec] | None = None,
        blue_sentry: BlueSentry | None = None,
    ) -> None:
        self._eng = engagement
        self._specs = specs or self._load_default_specs()
        self._blue = blue_sentry
        self._objective: tuple[str, str] | None = None

    @staticmethod
    def _load_default_specs() -> dict[Archetype, AgentSpec]:
        return {s.archetype: s for s in load_specs(_SPECS_DIR)}

    @property
    def _store(self) -> KnowledgeStore:
        return self._eng.store

    @property
    def _ctx(self) -> AgentContext:
        return self._eng.context

    @property
    def _engagement_id(self) -> str:
        return self._eng.scope.engagement_id

    # --- the loop -------------------------------------------------------------

    def run(
        self,
        targets: list[str],
        *,
        goal: str = "assess",
        objective: tuple[str, str] | None = None,
    ) -> LoopResult:
        self._objective = objective
        plan = build_plan(goal, targets, self._store.graph)
        if self._blue is not None and self._ctx.event_bus is not None:
            self._blue.attach(self._ctx.event_bus)
        self._ctx.audit.append(
            engagement_id=self._engagement_id,
            actor="orchestrator",
            action="plan.built",
            payload={"goal": goal, "phases": plan.phase_names(), "targets": list(targets)},
        )

        for phase in plan.phases:
            self._emit(EventType.PHASE_STARTED, payload={"phase": phase.name})
            self._dispatch(phase, plan)
            self._emit(EventType.PHASE_COMPLETED, payload={"phase": phase.name})

        report = self._build_report(goal, retests=[])
        self._emit(EventType.REPORT_GENERATED, payload={"confirmed": len(report.confirmed)})
        return LoopResult(plan=plan, report=report, retests=[])

    def _dispatch(self, phase: Phase, plan: AttackPlan) -> None:
        if phase.name == "recon":
            self._run_agent(Archetype.RECON, plan.prioritized_targets)
        elif phase.name in ("verify_services", "verify_vulns"):
            self._eng.verify()
        elif phase.name == "web":
            targets = self._web_targets()
            if targets:
                self._run_agent(Archetype.WEB, targets)
        elif phase.name == "exploit_confirm":
            # SQLMap-driven candidate confirmation (Exploit-Confirmer agent)...
            self._run_agent(Archetype.EXPLOIT, plan.prioritized_targets)
            # ...plus the gated exploit-module confirmations (SSTI/RCE/traversal/…).
            self._eng.exploit()
        elif phase.name == "correlate":
            self._eng.correlate()
        elif phase.name == "convert":
            self._run_agent(Archetype.REMEDIATOR, [])
        elif phase.name == "report":
            pass  # produced after the loop completes

    def _run_agent(self, archetype: Archetype, targets: list[str]) -> None:
        spec = self._specs.get(archetype)
        if spec is None:
            _log.warning("no spec for archetype; skipping", archetype=archetype.value)
            return
        # Bind the spec's scope reference to this engagement for a clean record.
        spec = spec.model_copy(update={"scope_ref": self._engagement_id})
        build_agent(spec, self._ctx, self._eng.registry).run(targets)

    def _web_targets(self) -> list[str]:
        """Build URL targets for reachable web services discovered in recon."""

        return web_targets(self._store)

    # --- close the loop (gated, real-world effect) ----------------------------

    def close_loop(self) -> list[RetestResult]:
        """Apply approved remediations and re-test; escalate what persists.

        For each confirmed finding with a proposed remediation, this requests the
        ``apply_fix`` human gate (via the Converter), and — only if approved and
        applied — re-runs the exact confirming check. A fix that holds marks the
        remediation ``verified_fixed``; a persistent finding is escalated with
        failed-retest evidence.
        """

        converter = self._converter()
        retester = RetestRunner(
            VerifyContext(
                engagement_id=self._engagement_id,
                tool_runner=self._eng.tool_runner,
                store=self._store,
                audit=self._ctx.audit,
            ),
            self._eng.feed,
        )
        results: list[RetestResult] = []
        for finding in self._store.findings(FindingState.CONFIRMED):
            proposals = self._store.remediations(finding.id)
            if not proposals:
                continue
            remediation = converter.apply(proposals[0])
            if remediation.status is not RemediationStatus.APPLIED:
                continue  # gate denied → do not re-test an unapplied change
            result = retester.retest(finding)
            results.append(result)
            self._record_retest(finding.id, remediation, result)
        return results

    def _record_retest(
        self, finding_id: str, remediation: Remediation, result: RetestResult
    ) -> None:
        new_status = (
            RemediationStatus.VERIFIED_FIXED if result.fixed else RemediationStatus.PERSISTED
        )
        self._store.update_remediation(remediation.model_copy(update={"status": new_status}))
        self._ctx.audit.append(
            engagement_id=self._engagement_id,
            actor="orchestrator",
            action="retest",
            payload={"finding_id": finding_id, "fixed": result.fixed, "detail": result.detail},
        )
        if result.fixed:
            self._emit(EventType.RETEST_PASSED, finding_id=finding_id,
                       payload={"detail": result.detail})
        else:
            self._emit(EventType.RETEST_FAILED, finding_id=finding_id,
                       payload={"detail": result.detail})
            self._emit(EventType.FINDING_ESCALATED, finding_id=finding_id,
                       payload={"detail": "fix did not hold on re-test"})

    def _converter(self) -> Converter:
        spec = self._specs[Archetype.REMEDIATOR].model_copy(
            update={"scope_ref": self._engagement_id}
        )
        agent = build_agent(spec, self._ctx, self._eng.registry)
        assert isinstance(agent, Converter)
        return agent

    # --- reporting ------------------------------------------------------------

    def build_report(self, goal: str, retests: list[RetestResult]) -> EngagementReport:
        return self._build_report(goal, retests=retests)

    def _build_report(self, goal: str, retests: list[RetestResult]) -> EngagementReport:
        audit = self._ctx.audit
        head = audit.head()
        kill_chain: KillChainPlan | None = None
        if self._objective is not None:
            kill_chain = KillChainPlanner(self._store).plan(*self._objective)
        return build_report(
            engagement_id=self._engagement_id,
            goal=goal,
            findings=self._store.findings(),
            remediations=self._store.remediations(),
            asset_count=len(self._store.assets()),
            audit_entries=len(audit),
            audit_intact=audit.verify(),
            audit_head=head.entry_hash if head else None,
            retests=retests,
            blue_alerts=self._blue.report.alert_count if self._blue else 0,
            attack_paths=build_attack_paths(self._store),
            kill_chain=kill_chain,
            attack_surface=build_attack_surface(self._store),
        )

    def _emit(self, event: EventType, **kwargs: object) -> None:
        bus = self._ctx.event_bus
        if bus is None:
            return
        bus.publish(
            Event(event=event, engagement_id=self._engagement_id,
                  emitted_by="orchestrator", **kwargs)
        )
