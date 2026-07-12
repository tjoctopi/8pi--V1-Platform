"""Autonomous campaign runner (O1) tests."""

from __future__ import annotations

from attack_engine.knowledge.store import KnowledgeStore
from attack_engine.orchestrator.campaign import (
    CampaignResult,
)
from attack_engine.orchestrator.profiles import (
    BUILTIN_PROFILES,
    get_profile,
    load_profile,
)
from attack_engine.orchestrator.report import build_report
from attack_engine.schemas.findings import Asset, Finding, FindingState, Priority, Service

# --- profiles -----------------------------------------------------------------

def test_builtin_profiles_load() -> None:
    p = get_profile("web-opportunist")
    assert p.autonomy_tier == 1
    assert "exploit_confirm" in p.techniques
    assert "network-intruder" in BUILTIN_PROFILES


def test_custom_profile_from_yaml(tmp_path) -> None:
    y = tmp_path / "actor.yaml"
    y.write_text(
        "id: apt-x\nname: APT-X\ndescription: test\n"
        "autonomy_tier: 2\ntechniques: [exploit_confirm, T1078, lateral_movement]\n"
    )
    p = load_profile(y)
    assert p.id == "apt-x" and p.autonomy_tier == 2
    assert p.techniques == frozenset({"exploit_confirm", "T1078", "lateral_movement"})


# --- CampaignResult presentation ---------------------------------------------

def _confirm(store, asset, type_, prob, priority):
    f = store.propose_finding(Finding(
        engagement_id=store.engagement_id, asset=asset, type=type_,
        exploit_prob=prob, priority=priority))
    store.promote_finding(f.id, FindingState.VERIFIED, verified_by="oracle")
    return store.promote_finding(f.id, FindingState.CONFIRMED)


def test_result_markdown_reports_reached_and_pending() -> None:
    # A confirmed foothold on the objective host at 'user' → reachable + confirmed.
    store = KnowledgeStore("engagement-camp")
    store.add_asset(Asset(address="10.5.0.10", engagement_id="engagement-camp",
                          services=(Service(port=3000),)))
    _confirm(store, "10.5.0.10", "sqli-boolean-blind", 0.95, Priority.HIGH)
    report = build_report(
        engagement_id="engagement-camp", goal="campaign", findings=store.findings(),
        remediations=[], asset_count=1, audit_entries=5, audit_intact=True,
        audit_head=None,
    )
    result = CampaignResult(
        engagement_id="engagement-camp", objective="10.5.0.10:user",
        profile="Opportunistic Web Attacker", reached=True, iterations=1,
        autonomous_actions=3, gated_actions=0, confirmed_footholds=1,
        pending_capabilities=[], report=report,
    )
    md = result.to_markdown()
    assert "REACHED" in md
    assert "Opportunistic Web Attacker" in md
    assert "10.5.0.10:user" in md


def test_result_flags_unauthorized_and_pending() -> None:
    result = CampaignResult(
        engagement_id="e", objective="10.5.0.99:root", profile="Network Intruder",
        reached=False, iterations=2, autonomous_actions=1, gated_actions=2,
        confirmed_footholds=1,
        pending_capabilities=["privilege_escalation (T1068): local privesc — needs ..."],
        unauthorized_techniques=["lateral_movement"],
    )
    md = result.to_markdown()
    assert "NOT REACHED" in md
    assert "did NOT authorize" in md and "lateral_movement" in md
    assert "Pending capabilities" in md and "privilege_escalation" in md
