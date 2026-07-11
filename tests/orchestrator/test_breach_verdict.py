"""Breachability verdict synthesis tests."""

from __future__ import annotations

from attack_engine.knowledge.store import KnowledgeStore
from attack_engine.orchestrator.attackpath import build_attack_paths
from attack_engine.orchestrator.report import build_breach_verdict
from attack_engine.schemas.findings import Asset, Finding, FindingState, Priority, Service


def _confirmed(store, asset, type_, prob, priority, verified="oracle"):
    f = store.propose_finding(Finding(
        engagement_id=store.engagement_id, asset=asset, type=type_,
        exploit_prob=prob, priority=priority))
    store.promote_finding(f.id, FindingState.VERIFIED, verified_by=verified)
    return store.promote_finding(f.id, FindingState.CONFIRMED)


def _verdict(store):
    confirmed = list(store.findings(FindingState.CONFIRMED))
    return build_breach_verdict(confirmed, build_attack_paths(store))


def test_reachable_confirmed_vuln_is_breachable() -> None:
    store = KnowledgeStore("eng-1")
    store.add_asset(Asset(address="10.5.0.10", engagement_id="eng-1",
                          services=(Service(port=3000),)))
    _confirmed(store, "10.5.0.10", "sqli-boolean-blind", 0.95, Priority.HIGH)

    verdict = _verdict(store)
    assert verdict.breachable is True
    assert len(verdict.footholds) == 1
    fh = verdict.footholds[0]
    assert fh.asset == "10.5.0.10"
    assert fh.technique == "T1190"          # SQLi → exploitation of public app
    assert fh.entry_path[0] == "entry"      # a real route from entry was mapped
    assert "BREACHABLE" in verdict.summary()


def test_unreachable_vuln_is_not_breachable() -> None:
    store = KnowledgeStore("eng-1")
    store.add_asset(Asset(address="10.5.0.99", engagement_id="eng-1"),
                    reachable_from_entry=False)
    _confirmed(store, "10.5.0.99", "sqli-boolean-blind", 0.9, Priority.HIGH)

    verdict = _verdict(store)
    assert verdict.breachable is False       # confirmed but unreachable ⇒ no path
    assert "NOT BREACHABLE" in verdict.summary()


def test_informational_finding_is_not_a_vector() -> None:
    store = KnowledgeStore("eng-1")
    store.add_asset(Asset(address="10.5.0.10", engagement_id="eng-1"))
    _confirmed(store, "10.5.0.10", "web:missing-headers", 0.1, Priority.INFORMATIONAL)
    assert _verdict(store).breachable is False


def test_footholds_ranked_by_exploit_probability() -> None:
    store = KnowledgeStore("eng-1")
    store.add_asset(Asset(address="10.5.0.10", engagement_id="eng-1"))
    _confirmed(store, "10.5.0.10", "ssti", 0.6, Priority.HIGH)
    _confirmed(store, "10.5.0.10", "command-injection", 0.98, Priority.PATCH_IMMEDIATELY)
    verdict = _verdict(store)
    assert [fh.finding_type for fh in verdict.footholds] == [
        "command-injection", "ssti",
    ]
