"""Reasoning loop — adaptation, stop conditions, budget, and the LLM planner.

The point of the loop is that step N+1 depends on what step N observed. These
tests prove that with fakes, then exercise the real ``LlmPlanner`` path offline
against the mock provider.
"""

from __future__ import annotations

from attack_engine.agents.actions import (
    ActionOutcome,
    ActionPlan,
    ProposedAction,
)
from attack_engine.agents.reasoning import (
    HeuristicReflector,
    LlmPlanner,
    LoopContext,
    ReasoningLoop,
)
from attack_engine.config import Settings
from attack_engine.gateway.budget import TokenBudget
from attack_engine.gateway.provider import MockProvider
from attack_engine.gateway.router import ModelGateway
from attack_engine.knowledge.worldmodel import WorldModel
from attack_engine.schemas.beliefs import Observation

# --- fakes ----------------------------------------------------------------------


class _RecordingActor:
    def __init__(self, ok: bool = True) -> None:
        self.calls: list[ProposedAction] = []
        self._ok = ok

    def act(self, action: ProposedAction) -> ActionOutcome:
        self.calls.append(action)
        return ActionOutcome(ok=self._ok, summary=f"ran {action.tool}")


class _HypothesisObserver:
    """Adds a lead the first time 'scan' runs — so the next plan can adapt."""

    def observe(self, action, outcome, ctx: LoopContext) -> None:
        if action.tool == "scan":
            ctx.world_model.add_hypothesis(
                subject="10.5.0.10", kind="cve", title="maybe vsftpd 2.3.4"
            )
        elif action.tool == "test":
            leads = ctx.world_model.open_hypotheses()
            if leads:
                ctx.world_model.observe(
                    leads[0].id, Observation(source="test", probability=0.8)
                )


class _AdaptivePlanner:
    """Scan until a lead exists, then test it, then finish — driven by state."""

    def propose(self, ctx: LoopContext) -> ActionPlan:
        leads = ctx.world_model.open_hypotheses()
        tested = any(s.action.tool == "test" for s in ctx.history)
        if not leads:
            return ActionPlan(actions=(ProposedAction(tool="scan", rationale="map"),))
        if not tested:
            return ActionPlan(
                actions=(ProposedAction(tool="test", rationale="probe lead", target=leads[0].subject),)
            )
        return ActionPlan(actions=(ProposedAction(tool="finish", rationale="done"),))


def _wm() -> WorldModel:
    return WorldModel(engagement_id="eng-1")


# --- adaptation -----------------------------------------------------------------


def test_loop_adapts_next_action_to_observations() -> None:
    actor = _RecordingActor()
    loop = ReasoningLoop(_AdaptivePlanner(), actor, _HypothesisObserver())
    wm = _wm()
    result = loop.run(wm, objective="map and probe 10.5.0.10")
    # scan (no leads) -> test (a lead now exists) -> finish
    assert [a.tool for a in actor.calls] == ["scan", "test"]
    assert result.stop_reason == "planner_finished"
    assert result.iterations == 2
    # the observation from 'test' raised the lead's confidence
    assert wm.open_hypotheses()[0].confidence > 0.3


def test_select_prefers_highest_expected_value() -> None:
    plan = ActionPlan(
        actions=(
            ProposedAction(tool="a", rationale="", expected_value=0.2),
            ProposedAction(tool="b", rationale="", expected_value=0.9),
            ProposedAction(tool="c", rationale="", expected_value=0.5),
        )
    )
    assert ReasoningLoop._select(plan).tool == "b"


def test_empty_plan_finishes() -> None:
    class _EmptyPlanner:
        def propose(self, ctx: LoopContext) -> ActionPlan:
            return ActionPlan()

    loop = ReasoningLoop(_EmptyPlanner(), _RecordingActor(), _HypothesisObserver())
    result = loop.run(_wm(), objective="x")
    assert result.stop_reason == "planner_finished"
    assert result.iterations == 0


# --- stop conditions ------------------------------------------------------------


def test_max_steps_cap() -> None:
    class _FreshScan:
        # a *distinct* action each step (varying target), so the loop keeps acting
        def propose(self, ctx: LoopContext) -> ActionPlan:
            return ActionPlan(actions=(
                ProposedAction(tool="scan", target=f"h{ctx.step}", rationale="loop"),
            ))

    # observer that never adds leads so the planner never finishes
    class _NoopObserver:
        def observe(self, action, outcome, ctx) -> None:
            return None

    loop = ReasoningLoop(_FreshScan(), _RecordingActor(), _NoopObserver(), max_steps=4)
    result = loop.run(_wm(), objective="x")
    assert result.stop_reason == "max_steps"
    assert result.iterations == 4


def test_skips_already_run_action_and_stops_when_exhausted() -> None:
    # A planner that always proposes the identical call must not spin: the loop
    # runs it once, then has nothing new to do → stops "exhausted" (progression,
    # not repetition — the reason a real loop moves on to other tools).
    class _AlwaysSameScan:
        def propose(self, ctx: LoopContext) -> ActionPlan:
            return ActionPlan(actions=(
                ProposedAction(tool="scan", target="h", rationale="loop"),
            ))

    class _NoopObserver:
        def observe(self, action, outcome, ctx) -> None:
            return None

    actor = _RecordingActor()
    loop = ReasoningLoop(_AlwaysSameScan(), actor, _NoopObserver(), max_steps=5)
    result = loop.run(_wm(), objective="x")
    assert result.stop_reason == "exhausted"
    assert len(actor.calls) == 1  # ran the tool exactly once, no wasteful repeats


def test_reflector_stuck_on_no_progress() -> None:
    class _AlwaysScan:
        def propose(self, ctx: LoopContext) -> ActionPlan:
            return ActionPlan(actions=(ProposedAction(tool="scan", rationale="x"),))

    class _NoopObserver:
        def observe(self, action, outcome, ctx) -> None:
            return None

    loop = ReasoningLoop(
        _AlwaysScan(),
        _RecordingActor(ok=False),  # every action unproductive
        _NoopObserver(),
        reflector=HeuristicReflector(max_no_progress=2),
    )
    result = loop.run(_wm(), objective="x")
    assert result.stop_reason == "stuck"
    assert result.iterations == 2


def test_budget_exhaustion_stops_loop() -> None:
    class _AlwaysScan:
        def propose(self, ctx: LoopContext) -> ActionPlan:
            return ActionPlan(actions=(ProposedAction(tool="scan", rationale="x"),))

    class _NoopObserver:
        def observe(self, action, outcome, ctx) -> None:
            return None

    from attack_engine.gateway.types import Usage

    budget = TokenBudget(max_total_tokens=100)
    # Pre-exhaust the budget so the very first ensure_available trips.
    budget.charge(Usage(prompt_tokens=100, completion_tokens=1))
    loop = ReasoningLoop(_AlwaysScan(), _RecordingActor(), _NoopObserver())
    result = loop.run(_wm(), objective="x", budget=budget)
    assert result.stop_reason == "budget_exhausted"
    assert result.iterations == 0


# --- LlmPlanner (real path, offline) --------------------------------------------


def test_llm_planner_returns_action_plan() -> None:
    plan_json = (
        '{"assessment": "port 3000 open", "actions": ['
        '{"tool": "httpx", "rationale": "probe web", "target": "10.5.0.10", '
        '"params": {}, "expected_value": 0.8}]}'
    )
    gw = ModelGateway(
        settings=Settings(model_mock=True),
        provider=MockProvider(responder=lambda _m: plan_json),
    )
    planner = LlmPlanner(gw, tools=["nmap", "httpx", "ffuf"], system_prompt="You are Recon.")
    wm = _wm()
    ctx = LoopContext(wm, objective="map target", history=(), step=0, budget=None)
    plan = planner.propose(ctx)
    assert isinstance(plan, ActionPlan)
    assert plan.actions[0].tool == "httpx"
    assert plan.actions[0].expected_value == 0.8


def test_llm_planner_drives_the_loop() -> None:
    # Model proposes one real action, then finishes.
    replies = iter(
        [
            '{"actions": [{"tool": "nmap", "rationale": "scan", "expected_value": 0.9}]}',
            '{"actions": [{"tool": "finish", "rationale": "done", "expected_value": 1.0}]}',
        ]
    )
    gw = ModelGateway(
        settings=Settings(model_mock=True),
        provider=MockProvider(responder=lambda _m: next(replies)),
    )
    planner = LlmPlanner(gw, tools=["nmap"], system_prompt="You are Recon.")
    actor = _RecordingActor()
    loop = ReasoningLoop(planner, actor, _HypothesisObserver())
    result = loop.run(_wm(), objective="map target")
    assert [a.tool for a in actor.calls] == ["nmap"]
    assert result.stop_reason == "planner_finished"
