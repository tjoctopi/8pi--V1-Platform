"""Autonomous adversary campaign (Phase F): specialist sequencing + frontier
expansion + governance, driven with fake specialist loops that mutate the world
model deterministically (the real ObjectiveController and objectives are exercised).
"""

from __future__ import annotations

from collections.abc import Callable

from attack_engine.ad.graph import ADEdgeType, ADGraph, PrincipalKind
from attack_engine.agents.actions import ReasoningResult
from attack_engine.gateway.budget import TokenBudget
from attack_engine.governance.audit import AuditLog
from attack_engine.governance.authorization import KillSwitch
from attack_engine.knowledge.worldmodel import WorldModel
from attack_engine.orchestrator.adversary import AdversaryCampaign, CampaignPhase
from attack_engine.orchestrator.objective import (
    ConfidenceObjective,
    DomainAdminObjective,
)
from attack_engine.schemas import RulesOfEngagement, Scope


def _scope() -> Scope:
    return Scope(
        engagement_id="eng-f", allowed_cidrs=("10.5.0.0/24",),
        roe=RulesOfEngagement(autonomy_tier=1),
        authorized_by="lead@8pi.ai", signature="signed",
    )


class _FakeLoop:
    """A specialist loop stand-in: applies a scripted mutation, then reports done."""

    def __init__(self, mutate: Callable[[WorldModel, int], None]) -> None:
        self._mutate = mutate
        self.calls = 0

    def run(self, world_model, objective, *, budget=None, stop_when=None):
        self.calls += 1
        self._mutate(world_model, self.calls)
        return ReasoningResult(stop_reason="planner_finished")


def _add_surface(wm: WorldModel, _call: int) -> None:
    if wm.find_hypothesis(kind="surface", subject="10.5.0.20") is None:
        wm.add_hypothesis(subject="10.5.0.20", kind="surface", title="host mapped",
                          rationale="open ports", prior=0.9, created_by="recon")


def _own_domain_admin(wm: WorldModel, _call: int) -> None:
    g = ADGraph()
    g.add_principal("svc_sql@CORP.LOCAL", PrincipalKind.USER)
    g.add_principal("Domain Admins", PrincipalKind.GROUP, high_value=True)
    g.add_edge("SVC_SQL@CORP.LOCAL", "DOMAIN ADMINS", ADEdgeType.GENERIC_ALL)
    wm.set_ad_graph(g)
    wm.mark_owned("svc_sql@CORP.LOCAL")


def _noop(_wm: WorldModel, _call: int) -> None:
    return None


def _campaign(phases, goal, *, wm=None, kill=None, budget=None, max_rounds=4):
    audit = AuditLog()
    return AdversaryCampaign(
        scope=_scope(), world_model=wm or WorldModel("eng-f"), audit=audit,
        phases=phases, goal=goal, kill_switch=kill, budget=budget,
        max_rounds=max_rounds, profile_name="apt-test",
    ), audit


# --- reaching the goal ----------------------------------------------------------


def test_campaign_reaches_domain_admin_across_phases() -> None:
    phases = [
        CampaignPhase("recon", _FakeLoop(_add_surface),
                      ConfidenceObjective(kind="surface", threshold=0.8)),
        CampaignPhase("identity", _FakeLoop(_own_domain_admin), DomainAdminObjective()),
    ]
    campaign, audit = _campaign(phases, DomainAdminObjective())
    outcome = campaign.run()

    assert outcome.goal_reached
    assert outcome.stop_reason == "objective_reached"
    assert "SVC_SQL@CORP.LOCAL" in outcome.owned_frontier
    # both specialists ran and met their objective
    assert {p.name for p in outcome.phases} == {"recon", "identity"}
    assert all(p.met for p in outcome.phases)


def test_goal_already_satisfied_short_circuits() -> None:
    wm = WorldModel("eng-f")
    _own_domain_admin(wm, 1)  # a DA path exists before the campaign starts
    campaign, _ = _campaign([CampaignPhase("identity", _FakeLoop(_noop),
                                           DomainAdminObjective())],
                            DomainAdminObjective(), wm=wm)
    outcome = campaign.run()
    assert outcome.goal_reached and outcome.stop_reason == "already_satisfied"
    assert outcome.rounds == 0 and outcome.phases == []


# --- frontier expansion over rounds ---------------------------------------------


def test_frontier_expansion_reaches_goal_in_second_round() -> None:
    def stepwise(wm: WorldModel, call: int) -> None:
        if call == 1:
            wm.mark_owned("alice@CORP.LOCAL")          # ground gained, but no DA path
        else:
            _own_domain_admin(wm, call)                 # 2nd round: path to DA appears

    phases = [CampaignPhase("identity", _FakeLoop(stepwise), DomainAdminObjective())]
    campaign, _ = _campaign(phases, DomainAdminObjective())
    outcome = campaign.run()

    assert outcome.goal_reached
    assert outcome.rounds == 2                          # needed a second vantage
    assert outcome.stop_reason == "objective_reached"


def test_campaign_converges_when_no_new_ground() -> None:
    phases = [CampaignPhase("recon", _FakeLoop(_noop),
                            ConfidenceObjective(kind="surface"))]
    campaign, _ = _campaign(phases, DomainAdminObjective())
    outcome = campaign.run()
    assert not outcome.goal_reached
    assert outcome.stop_reason == "converged"
    assert outcome.rounds == 1                          # stopped once the frontier stalled


# --- governance: kill switch + budget -------------------------------------------


def test_kill_switch_before_start_runs_nothing() -> None:
    kill = KillSwitch()
    kill.trip("operator halt")
    phases = [CampaignPhase("identity", _FakeLoop(_own_domain_admin),
                            DomainAdminObjective())]
    campaign, _ = _campaign(phases, DomainAdminObjective(), kill=kill)
    outcome = campaign.run()
    assert outcome.stop_reason == "kill_switch"
    assert not outcome.goal_reached and outcome.phases == []


def test_kill_switch_mid_campaign_halts() -> None:
    kill = KillSwitch()

    def own_then_halt(wm: WorldModel, call: int) -> None:
        wm.mark_owned("alice@CORP.LOCAL")   # grows frontier so a next round is due
        kill.trip("operator halt")          # ...but the operator halts

    phases = [CampaignPhase("identity", _FakeLoop(own_then_halt), DomainAdminObjective())]
    campaign, _ = _campaign(phases, DomainAdminObjective(), kill=kill)
    outcome = campaign.run()
    assert outcome.stop_reason == "kill_switch"
    assert not outcome.goal_reached


def test_budget_exhausted_stops_campaign() -> None:
    budget = TokenBudget(max_total_tokens=0)  # nothing to spend
    phases = [CampaignPhase("identity", _FakeLoop(_own_domain_admin),
                            DomainAdminObjective())]
    campaign, _ = _campaign(phases, DomainAdminObjective(), budget=budget)
    outcome = campaign.run()
    assert outcome.stop_reason == "budget_exhausted"
    assert outcome.phases == []


# --- audit + reporting ----------------------------------------------------------


def test_campaign_is_audited_and_chain_intact() -> None:
    phases = [CampaignPhase("identity", _FakeLoop(_own_domain_admin),
                            DomainAdminObjective())]
    campaign, audit = _campaign(phases, DomainAdminObjective())
    outcome = campaign.run()
    actions = [e.action for e in audit.entries("eng-f")]
    assert "campaign.start" in actions and "campaign.complete" in actions
    assert outcome.audit_intact and audit.verify()


def test_outcome_to_markdown_smoke() -> None:
    phases = [CampaignPhase("identity", _FakeLoop(_own_domain_admin),
                            DomainAdminObjective())]
    campaign, _ = _campaign(phases, DomainAdminObjective())
    md = campaign.run().to_markdown()
    assert "# Adversary campaign — apt-test" in md
    assert "REACHED" in md
