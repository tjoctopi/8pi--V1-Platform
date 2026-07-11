"""Attack-path (kill-chain) construction tests."""

from __future__ import annotations

from attack_engine.knowledge.store import KnowledgeStore
from attack_engine.orchestrator.attackpath import build_attack_paths
from attack_engine.schemas.findings import Asset, Finding, FindingState, Priority, Service


def _confirmed(store, asset, type_, prob, priority, verified="oracle"):
    f = store.propose_finding(Finding(
        engagement_id=store.engagement_id, asset=asset, type=type_,
        exploit_prob=prob, priority=priority))
    store.promote_finding(f.id, FindingState.VERIFIED, verified_by=verified)
    return store.promote_finding(f.id, FindingState.CONFIRMED)


def test_reachable_target_produces_chain() -> None:
    store = KnowledgeStore("eng-1")
    store.add_asset(Asset(address="10.5.0.10", engagement_id="eng-1",
                          services=(Service(port=80),)))
    _confirmed(store, "10.5.0.10", "path-traversal", 0.97, Priority.HIGH)

    chains = build_attack_paths(store)
    assert len(chains) == 1
    chain = chains[0]
    assert chain.target == "10.5.0.10"
    assert chain.reachable is True
    assert chain.path[0] == "entry"
    assert "10.5.0.10" in chain.path
    assert chain.score == 0.97
    assert "path-traversal" in chain.finding_types


def test_unreachable_target_scores_zero() -> None:
    store = KnowledgeStore("eng-1")
    store.add_asset(Asset(address="10.5.0.99", engagement_id="eng-1"),
                    reachable_from_entry=False)
    _confirmed(store, "10.5.0.99", "sqli-boolean-blind", 0.9, Priority.HIGH)

    chains = build_attack_paths(store)
    assert chains[0].reachable is False
    assert chains[0].score == 0.0  # can't be reached → can't top the kill chain


def test_informational_findings_excluded() -> None:
    store = KnowledgeStore("eng-1")
    store.add_asset(Asset(address="10.5.0.5", engagement_id="eng-1"))
    _confirmed(store, "10.5.0.5", "CVE-INTERNAL", 0.1, Priority.INFORMATIONAL)
    assert build_attack_paths(store) == []


def test_chains_ranked_by_score() -> None:
    store = KnowledgeStore("eng-1")
    for addr in ("10.5.0.10", "10.5.0.11"):
        store.add_asset(Asset(address=addr, engagement_id="eng-1"))
    _confirmed(store, "10.5.0.10", "ssti", 0.7, Priority.HIGH)
    _confirmed(store, "10.5.0.11", "path-traversal", 0.97, Priority.PATCH_IMMEDIATELY)
    chains = build_attack_paths(store)
    assert [c.target for c in chains] == ["10.5.0.11", "10.5.0.10"]  # highest risk first
