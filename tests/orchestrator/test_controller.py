"""Objective-driven controller + typed objectives."""

from __future__ import annotations

from attack_engine.agents.actions import ActionOutcome, ActionPlan, ProposedAction
from attack_engine.agents.reasoning import LoopContext, ReasoningLoop
from attack_engine.knowledge.store import KnowledgeStore
from attack_engine.knowledge.worldmodel import WorldModel
from attack_engine.orchestrator.controller import ObjectiveController
from attack_engine.orchestrator.objective import (
    ConfidenceObjective,
    MapSurfaceObjective,
)
from attack_engine.schemas.beliefs import Observation
from attack_engine.schemas.findings import Asset, Service


def _wm(store: KnowledgeStore | None = None) -> WorldModel:
    return WorldModel(engagement_id="eng-1", store=store)


# --- objectives -----------------------------------------------------------------


def test_map_surface_objective_counts_assets_and_leads() -> None:
    store = KnowledgeStore("eng-1")
    store.add_asset(Asset(address="10.5.0.10", engagement_id="eng-1",
                          services=(Service(port=80),)), reachable_from_entry=True)
    wm = _wm(store)
    obj = MapSurfaceObjective(min_assets=1, min_hypotheses=1)
    assert not obj.is_satisfied(wm)  # asset yes, but no lead yet
    wm.add_hypothesis(subject="10.5.0.10", kind="cve", title="x")
    assert obj.is_satisfied(wm)


def test_confidence_objective_matches_kind_and_threshold() -> None:
    wm = _wm()
    h = wm.add_hypothesis(subject="ep", kind="sqli", title="x")
    obj = ConfidenceObjective(kind="sqli", threshold=0.75)
    assert not obj.is_satisfied(wm)
    wm.observe(h.id, Observation(source="probe", probability=0.8))
    assert obj.is_satisfied(wm)  # fused confidence now clears the threshold


# --- controller -----------------------------------------------------------------


def test_controller_returns_early_when_already_satisfied() -> None:
    wm = _wm()
    wm.add_hypothesis(subject="ep", kind="sqli", title="x", prior=0.9)
    loop = ReasoningLoop(_NeverPlanner(), _NoopActor(), _NoopObserver())
    result = ObjectiveController(loop).pursue(wm, ConfidenceObjective(kind="sqli", threshold=0.8))
    assert result.objective_met
    assert result.stop_reason == "already_satisfied"
    assert result.iterations == 0


def test_controller_stops_when_objective_becomes_satisfied() -> None:
    wm = _wm()
    wm.add_hypothesis(subject="ep", kind="sqli", title="param q")
    loop = ReasoningLoop(_ProbePlanner(), _NoopActor(), _RaiseConfidenceObserver())
    result = ObjectiveController(loop).pursue(wm, ConfidenceObjective(kind="sqli", threshold=0.75))
    assert result.objective_met
    assert result.stop_reason == "objective_satisfied"
    assert result.iterations == 1  # one probe raised confidence past threshold


def test_controller_reports_unmet_when_loop_finishes_early() -> None:
    wm = _wm()
    loop = ReasoningLoop(_NeverPlanner(), _NoopActor(), _NoopObserver())
    result = ObjectiveController(loop).pursue(wm, MapSurfaceObjective(min_assets=5))
    assert not result.objective_met
    assert result.stop_reason == "planner_finished"


# --- fakes ----------------------------------------------------------------------


class _NoopActor:
    def act(self, action: ProposedAction) -> ActionOutcome:
        return ActionOutcome(ok=True, summary="noop")


class _NoopObserver:
    def observe(self, action, outcome, ctx) -> None:
        return None


class _NeverPlanner:
    def propose(self, ctx: LoopContext) -> ActionPlan:
        return ActionPlan()  # empty -> loop finishes immediately


class _ProbePlanner:
    def propose(self, ctx: LoopContext) -> ActionPlan:
        return ActionPlan(actions=(ProposedAction(tool="probe", rationale="raise conf"),))


class _RaiseConfidenceObserver:
    def observe(self, action, outcome, ctx: LoopContext) -> None:
        leads = ctx.world_model.open_hypotheses()
        if leads:
            ctx.world_model.observe(leads[0].id, Observation(source="probe", probability=0.8))
