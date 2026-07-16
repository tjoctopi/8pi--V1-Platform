"""Web chaining engine — compose escalation paths from strong beliefs and light
up rungs as deterministic oracles confirm them.

A chain is proposal-space (a plan); a rung goes ``confirmed`` only when a matching
CONFIRMED finding exists — never from the plan alone (rule #1).
"""

from __future__ import annotations

from attack_engine.agents.web_chain import WebChainer
from attack_engine.knowledge.store import KnowledgeStore
from attack_engine.knowledge.worldmodel import WorldModel
from attack_engine.schemas.findings import Finding, FindingState


def _strong_lead(wm: WorldModel, kind: str, subject: str, confidence: float = 0.9):
    from attack_engine.schemas.beliefs import Observation

    return wm.add_hypothesis(
        subject=subject, kind=kind, title=f"{kind} lead", prior=0.5,
        observations=(Observation(source="t", probability=confidence),),
    )


def _confirm(store: KnowledgeStore, asset: str, ftype: str) -> Finding:
    f = store.propose_finding(
        Finding(engagement_id=store.engagement_id, asset=asset, type=ftype), emitted_by="t"
    )
    store.promote_finding(f.id, FindingState.VERIFIED, verified_by="oracle")
    return store.promote_finding(f.id, FindingState.CONFIRMED, verified_by="oracle")


def test_compose_builds_chain_from_ssrf_entry() -> None:
    wm = WorldModel("eng-1")
    _strong_lead(wm, "ssrf", "http://10.0.4.12/fetch?url")
    chains = WebChainer().compose(wm)
    assert len(chains) == 1
    c = chains[0]
    assert c.steps[0].kind == "ssrf" and c.steps[0].hypothesis_id is not None
    kinds = [s.kind for s in c.steps]
    assert kinds == ["ssrf", "cloud-metadata", "credential-access", "foothold"]
    assert not c.is_realised  # nothing proven yet
    assert c.confirmed_depth == 0


def test_compose_ignores_non_entry_classes_and_weak_leads() -> None:
    wm = WorldModel("eng-1")
    _strong_lead(wm, "xss", "http://10.0.4.12/s?q")  # xss heads no chain template
    _strong_lead(wm, "ssrf", "http://10.0.4.12/f?url", confidence=0.2)  # too weak
    assert WebChainer().compose(wm, min_confidence=0.5) == []


def test_compose_is_idempotent() -> None:
    wm = WorldModel("eng-1")
    _strong_lead(wm, "lfi", "http://10.0.4.12/p?file")
    WebChainer().compose(wm)
    WebChainer().compose(wm)
    assert len(wm.chains()) == 1  # not duplicated


def test_refresh_lights_up_confirmed_entry_rung() -> None:
    store = KnowledgeStore("eng-1")
    wm = WorldModel("eng-1", store=store)
    _strong_lead(wm, "ssrf", "http://10.0.4.12/fetch?url")
    WebChainer().compose(wm)
    # An oracle confirms the SSRF on that host...
    _confirm(store, "10.0.4.12", "ssrf")
    [chain] = WebChainer().refresh(wm)
    assert chain.steps[0].confirmed and chain.steps[0].finding_id is not None
    assert chain.confirmed_depth == 1  # entry rung proven; downstream still open
    assert not chain.is_realised


def test_confirmed_cmdi_realises_the_foothold_chain() -> None:
    # Command execution proves both the cmdi rung AND the foothold rung → the
    # short cmdi chain is fully realised (a landed web foothold primitive).
    store = KnowledgeStore("eng-1")
    wm = WorldModel("eng-1", store=store)
    _strong_lead(wm, "cmdi", "http://10.5.0.12/cmd?host")
    WebChainer().compose(wm)
    _confirm(store, "10.5.0.12", "command-injection")
    [chain] = WebChainer().refresh(wm)
    assert [s.kind for s in chain.steps] == ["cmdi", "foothold"]
    assert all(s.confirmed for s in chain.steps)
    assert chain.is_realised


def test_compose_refreshes_existing_and_matches_by_class_prefix() -> None:
    store = KnowledgeStore("eng-1")
    wm = WorldModel("eng-1", store=store)
    _strong_lead(wm, "sqli", "http://10.0.4.12/item?id")
    _confirm(store, "10.0.4.12", "sqli-boolean-blind")  # confirmed BEFORE compose
    [chain] = WebChainer().compose(wm)
    assert chain.steps[0].kind == "sqli" and chain.steps[0].confirmed
    assert chain.confirmed_depth == 1
