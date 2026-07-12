"""Kill-chain planner tests — goal-directed, confirmed vs planned, gated."""

from __future__ import annotations

from attack_engine.killchain.plan import KillChainPhase, KillChainPlanner
from attack_engine.knowledge.store import KnowledgeStore
from attack_engine.schemas.findings import Asset, Finding, FindingState, Priority


def _foothold(store: KnowledgeStore, host: str, type_: str = "path-traversal",
              prob: float = 0.95) -> Finding:
    store.add_asset(Asset(address=host, engagement_id=store.engagement_id))
    f = store.propose_finding(Finding(
        engagement_id=store.engagement_id, asset=host, type=type_,
        exploit_prob=prob, priority=Priority.HIGH, metadata={"technique": "T1190"}))
    store.promote_finding(f.id, FindingState.VERIFIED, verified_by="module")
    return store.promote_finding(f.id, FindingState.CONFIRMED)


def test_initial_access_only_is_fully_confirmed() -> None:
    store = KnowledgeStore("e")
    _foothold(store, "10.5.0.10")
    plan = KillChainPlanner(store).plan("10.5.0.10", "user")
    assert plan.reachable
    assert len(plan.steps) == 1
    assert plan.steps[0].phase is KillChainPhase.INITIAL_ACCESS
    assert plan.steps[0].confirmed is True
    assert plan.fully_confirmed is True


def test_multi_hop_route_to_internal_objective() -> None:
    store = KnowledgeStore("e")
    _foothold(store, "10.5.0.10")           # confirmed web foothold
    store.add_asset(Asset(address="10.5.0.99", engagement_id="e"))  # internal DB
    plan = KillChainPlanner(store).plan("10.5.0.99", "root")

    assert plan.reachable
    phases = [s.phase for s in plan.steps]
    assert phases[0] is KillChainPhase.INITIAL_ACCESS
    assert KillChainPhase.PRIVILEGE_ESCALATION in phases
    assert KillChainPhase.LATERAL_MOVEMENT in phases
    assert plan.steps[-1].phase is KillChainPhase.OBJECTIVE
    # Only the first hop is confirmed; the rest are clearly planned.
    assert plan.steps[0].confirmed and not plan.fully_confirmed


def test_every_impact_step_is_gated() -> None:
    store = KnowledgeStore("e")
    _foothold(store, "10.5.0.10")
    store.add_asset(Asset(address="10.5.0.99", engagement_id="e"))
    plan = KillChainPlanner(store).plan("10.5.0.99", "root")
    assert all(step.gated for step in plan.steps)  # kill-chain diagram: 4–7 gated


def test_steps_carry_attck_and_suggested_tools() -> None:
    store = KnowledgeStore("e")
    _foothold(store, "10.5.0.10")
    store.add_asset(Asset(address="10.5.0.99", engagement_id="e"))
    plan = KillChainPlanner(store).plan("10.5.0.99", "root")
    privesc = next(s for s in plan.steps if s.phase is KillChainPhase.PRIVILEGE_ESCALATION)
    assert privesc.technique == "T1068"
    assert "linpeas" in privesc.suggested_tools.lower()


def test_no_foothold_no_route() -> None:
    store = KnowledgeStore("e")
    store.add_asset(Asset(address="10.5.0.99", engagement_id="e"))  # no confirmed way in
    plan = KillChainPlanner(store).plan("10.5.0.99", "root")
    assert plan.reachable is False
    assert plan.steps == []


def test_markdown_render() -> None:
    store = KnowledgeStore("e")
    _foothold(store, "10.5.0.10")
    store.add_asset(Asset(address="10.5.0.99", engagement_id="e"))
    md = KillChainPlanner(store).plan("10.5.0.99", "root").to_markdown()
    assert "Objective 10.5.0.99/root" in md
    # Impact phases are flagged as gated-unless-authorized in the plan.
    assert "gated unless authorized" in md
