"""Lateral movement + campaign chaining (O6) tests."""

from __future__ import annotations

from attack_engine.ad import from_bloodhound
from attack_engine.knowledge.store import KnowledgeStore
from attack_engine.orchestrator.lateral import LateralPlanner
from attack_engine.schemas.findings import Asset, Finding, FindingState, Priority


def _foothold(store: KnowledgeStore, host: str) -> None:
    f = store.propose_finding(Finding(
        engagement_id=store.engagement_id, asset=host, type="rce",
        exploit_prob=0.9, priority=Priority.HIGH))
    store.promote_finding(f.id, FindingState.VERIFIED, verified_by="mod")
    store.promote_finding(f.id, FindingState.CONFIRMED)


def test_network_lateral_hop_to_reachable_objective() -> None:
    store = KnowledgeStore("eng-lat")
    store.add_asset(Asset(address="10.5.0.10", engagement_id="eng-lat"))
    store.add_asset(Asset(address="10.5.0.99", engagement_id="eng-lat"))  # reachable
    _foothold(store, "10.5.0.10")

    plan = LateralPlanner(store).plan("10.5.0.99")
    assert plan.reachable is True
    net_hops = [h for h in plan.hops if h.mechanism == "remote-service"]
    assert any(h.from_node == "10.5.0.10" and h.to_node == "10.5.0.99"
               and h.technique == "T1210" for h in net_hops)


def test_no_lateral_when_objective_unreachable() -> None:
    store = KnowledgeStore("eng-lat")
    store.add_asset(Asset(address="10.5.0.10", engagement_id="eng-lat"))
    store.add_asset(Asset(address="10.5.0.99", engagement_id="eng-lat"),
                    reachable_from_entry=False)  # unreachable objective
    _foothold(store, "10.5.0.10")
    plan = LateralPlanner(store).plan("10.5.0.99")
    assert not any(h.to_node == "10.5.0.99" for h in plan.hops)


def test_identity_lateral_folds_in_ad_path() -> None:
    store = KnowledgeStore("eng-lat")
    store.add_asset(Asset(address="10.5.0.10", engagement_id="eng-lat"))
    _foothold(store, "10.5.0.10")
    ad = from_bloodhound({
        "groups": [{"name": "Domain Admins@corp", "members": ["admin@corp"]},
                   {"name": "IT@corp", "members": ["alice@corp"]}],
        "computers": [{"name": "WS01@corp", "local_admins": ["IT@corp"],
                       "sessions": ["admin@corp"]}],
    })
    plan = LateralPlanner(store).plan("DC@corp", ad_graph=ad,
                                      owned_principals=["alice@corp"])
    identity = [h for h in plan.hops if h.mechanism == "identity"]
    assert identity, "AD attack path should contribute identity lateral hops"
    assert plan.reachable is True  # an AD path to Domain Admin exists
    assert "T1069" in {h.technique for h in identity}
