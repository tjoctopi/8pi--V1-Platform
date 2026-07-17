"""Recon specialist on the loop — the ToolRunnerActor, the belief observer, and
a full engine-backed run driven by the objective controller.

The end-to-end test uses the real Tool Runner with a fake sandbox (the shared
``ctx`` fixture) so a scripted model plan actually flows through the boundary,
nmap output is parsed, and the observer turns it into beliefs — no Docker, no
network, but the real wiring.
"""

from __future__ import annotations

import pytest

from attack_engine.agents.actions import ProposedAction
from attack_engine.agents.context import AgentContext
from attack_engine.agents.reasoning import LoopContext
from attack_engine.agents.recon_specialist import ReconObserver, build_recon_loop
from attack_engine.agents.tool_actor import ToolRunnerActor
from attack_engine.config import Settings
from attack_engine.errors import ScopeViolationError, ToolExecutionError
from attack_engine.gateway.provider import MockProvider
from attack_engine.gateway.router import ModelGateway
from attack_engine.knowledge.store import KnowledgeStore
from attack_engine.knowledge.worldmodel import WorldModel
from attack_engine.orchestrator.controller import ObjectiveController
from attack_engine.orchestrator.objective import MapSurfaceObjective
from attack_engine.schemas.tools import ToolResult


def _tool_result(tool: str, target: str, parsed: dict) -> ToolResult:
    return ToolResult(
        tool=tool, target=target, raw=b"", parsed=parsed, exit_code=0,
        audit_id="aud-1", engagement_id="eng-1",
    )


def _loop_ctx(wm: WorldModel) -> LoopContext:
    return LoopContext(wm, objective="map", history=(), step=0, budget=None)


# --- ToolRunnerActor ------------------------------------------------------------


class _FakeRunner:
    def __init__(self, result=None, error=None) -> None:
        self.result = result
        self.error = error
        self.calls: list[tuple[str, str]] = []

    def run(self, tool: str, target: str, profile=None):
        self.calls.append((tool, target))
        if self.error is not None:
            raise self.error
        return self.result


def test_actor_runs_tool_and_wraps_result() -> None:
    result = _tool_result("nmap", "10.0.4.12", {"ports": []})
    actor = ToolRunnerActor(_FakeRunner(result=result))
    outcome = actor.act(ProposedAction(tool="nmap", target="10.0.4.12", rationale="x"))
    assert outcome.ok
    assert outcome.raw is result


def test_actor_rejects_missing_target() -> None:
    actor = ToolRunnerActor(_FakeRunner())
    outcome = actor.act(ProposedAction(tool="nmap", rationale="x"))
    assert not outcome.ok
    assert "no target" in outcome.summary


def test_actor_degrades_on_scope_violation() -> None:
    actor = ToolRunnerActor(_FakeRunner(error=ScopeViolationError("9.9.9.9")))
    outcome = actor.act(ProposedAction(tool="nmap", target="9.9.9.9", rationale="x"))
    assert not outcome.ok
    assert "out-of-scope" in outcome.summary


def test_actor_degrades_on_tool_error() -> None:
    actor = ToolRunnerActor(_FakeRunner(error=ToolExecutionError("nmap", "t", "boom")))
    outcome = actor.act(ProposedAction(tool="nmap", target="10.0.4.12", rationale="x"))
    assert not outcome.ok
    assert "degraded" in outcome.summary


def test_actor_degrades_on_bad_tool_args() -> None:
    # A malformed tool call (missing required args → ValueError from build_argv)
    # must degrade, not crash the loop/campaign.
    actor = ToolRunnerActor(_FakeRunner(error=ValueError("bloodhound requires 'domain'")))
    outcome = actor.act(ProposedAction(tool="bloodhound", target="10.5.0.12", rationale="x"))
    assert not outcome.ok
    assert "invalid action" in outcome.summary


def test_actor_degrades_on_unknown_tool() -> None:
    # The planner can hallucinate a tool name; an unknown tool must degrade, not crash.
    from attack_engine.errors import ToolNotRegisteredError

    actor = ToolRunnerActor(_FakeRunner(error=ToolNotRegisteredError("web-surface")))
    outcome = actor.act(ProposedAction(tool="web-surface", target="10.5.0.12", rationale="x"))
    assert not outcome.ok
    assert "invalid action" in outcome.summary


# --- ReconObserver: recon output -> beliefs -------------------------------------


def test_observer_ingests_ports_into_assets_and_leads() -> None:
    store = KnowledgeStore("eng-1")
    wm = WorldModel("eng-1", store=store)
    result = _tool_result(
        "nmap", "10.0.4.12",
        {"ports": [
            {"port": 22, "protocol": "tcp", "service": "ssh"},
            {"port": 80, "protocol": "tcp", "service": "http",
             "product": "Apache httpd", "version": "2.4.49"},
        ]},
    )
    ReconObserver().observe(
        ProposedAction(tool="nmap", target="10.0.4.12", rationale="x"),
        _outcome(result), _loop_ctx(wm),
    )
    assert {a.address for a in wm.reachable_assets()} == {"10.0.4.12"}
    kinds = {h.kind for h in wm.open_hypotheses()}
    assert "cve" in kinds  # Apache 2.4.49 is a versioned CVE lead
    assert "web-surface" in kinds  # port 80 is web surface to enumerate


def test_observer_flags_sensitive_paths_higher() -> None:
    wm = WorldModel("eng-1")
    result = _tool_result(
        "ffuf", "http://10.0.4.12",
        {"results": [{"path": "admin", "status": 200}, {"path": "assets", "status": 200}]},
    )
    ReconObserver().observe(
        ProposedAction(tool="ffuf", target="http://10.0.4.12", rationale="x"),
        _outcome(result), _loop_ctx(wm),
    )
    by_kind = {h.kind: h for h in wm.open_hypotheses()}
    assert "exposure" in by_kind  # /admin is sensitive
    assert "web-path" in by_kind  # /assets is ordinary
    assert by_kind["exposure"].confidence > by_kind["web-path"].confidence


def test_observer_dedupes_repeated_signal() -> None:
    wm = WorldModel("eng-1")
    action = ProposedAction(tool="httpx", target="10.0.4.12", rationale="x")
    result = _tool_result("httpx", "10.0.4.12",
                          {"results": [{"webserver": "nginx", "tech": ["nginx"]}]})
    obs = ReconObserver()
    obs.observe(action, _outcome(result), _loop_ctx(wm))
    obs.observe(action, _outcome(result), _loop_ctx(wm))  # same signal again
    tech = [h for h in wm.hypotheses() if h.kind == "web-tech"]
    assert len(tech) == 1  # deduped, not duplicated
    assert len(tech[0].observations) == 2  # but reinforced


def test_observer_ignores_failed_outcome() -> None:
    wm = WorldModel("eng-1")
    from attack_engine.agents.actions import ActionOutcome

    ReconObserver().observe(
        ProposedAction(tool="nmap", target="t", rationale="x"),
        ActionOutcome(ok=False, summary="degraded", raw=None),
        _loop_ctx(wm),
    )
    assert wm.hypotheses() == []


# --- factory / guardrails -------------------------------------------------------


def test_build_recon_loop_requires_gateway(ctx: AgentContext) -> None:
    ctx.gateway = None
    with pytest.raises(ValueError, match="model gateway"):
        build_recon_loop(ctx)


# --- end-to-end through the real Tool Runner ------------------------------------


def test_recon_loop_maps_surface_end_to_end(ctx: AgentContext) -> None:
    calls = {"n": 0}

    def responder(_messages) -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            return (
                '{"actions": [{"tool": "nmap", "target": "10.0.4.12", '
                '"rationale": "map host", "expected_value": 0.9}]}'
            )
        return '{"actions": [{"tool": "finish", "rationale": "done", "expected_value": 1.0}]}'

    ctx.gateway = ModelGateway(
        settings=Settings(model_mock=True), provider=MockProvider(responder=responder)
    )
    wm = WorldModel(ctx.engagement_id, store=ctx.store)
    loop = build_recon_loop(ctx)
    result = ObjectiveController(loop).pursue(
        wm, MapSurfaceObjective(min_assets=1, min_hypotheses=1)
    )

    assert result.objective_met
    # The nmap output flowed through the real Tool Runner and became beliefs.
    assert "10.0.4.12" in {a.address for a in wm.reachable_assets()}
    assert any(h.kind == "cve" for h in wm.open_hypotheses())


def _outcome(result: ToolResult):
    from attack_engine.agents.actions import ActionOutcome

    return ActionOutcome(ok=True, summary="ok", raw=result)
