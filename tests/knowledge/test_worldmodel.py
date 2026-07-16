"""World Model v2 — hypotheses, fusion-based confidence, and planner queries."""

from __future__ import annotations

from attack_engine.knowledge.store import KnowledgeStore
from attack_engine.knowledge.worldmodel import WorldModel
from attack_engine.schemas.beliefs import HypothesisStatus, Observation
from attack_engine.schemas.findings import Asset, Service


def _wm(store: KnowledgeStore | None = None) -> WorldModel:
    return WorldModel(engagement_id="eng-1", store=store)


# --- hypotheses & fusion --------------------------------------------------------


def test_add_hypothesis_starts_at_prior() -> None:
    wm = _wm()
    h = wm.add_hypothesis(subject="10.5.0.10", kind="cve", title="maybe vsftpd 2.3.4")
    assert h.status is HypothesisStatus.OPEN
    assert h.confidence == h.prior == 0.3
    assert h.is_active


def test_agreeing_observations_raise_confidence() -> None:
    wm = _wm()
    h = wm.add_hypothesis(subject="ep", kind="sqli", title="param q looks injectable")
    h = wm.observe(h.id, Observation(source="dalfox", probability=0.7, note="quote error"))
    after_one = h.confidence
    assert after_one > 0.3  # a confident agreeing signal pushes belief up
    assert h.status is HypothesisStatus.TESTING  # first observation begins testing
    h = wm.observe(h.id, Observation(source="sqlmap-screen", probability=0.7))
    assert h.confidence > after_one  # independent agreement compounds


def test_contradicting_observation_lowers_confidence() -> None:
    wm = _wm()
    h = wm.add_hypothesis(subject="ep", kind="sqli", title="x", prior=0.6)
    h = wm.observe(h.id, Observation(source="probe", probability=0.1, note="no differential"))
    assert h.confidence < 0.6


def test_refute_marks_dead_and_drops_from_open() -> None:
    wm = _wm()
    h = wm.add_hypothesis(subject="ep", kind="idor", title="x")
    h = wm.refute(h.id, "auth actually enforced")
    assert h.status is HypothesisStatus.REFUTED
    assert not h.is_active
    assert h.confidence < 0.3
    assert h.id not in {o.id for o in wm.open_hypotheses()}


def test_link_finding_graduates_hypothesis() -> None:
    wm = _wm()
    h = wm.add_hypothesis(subject="ep", kind="rce", title="x")
    h = wm.link_finding(h.id, "f-123")
    assert h.finding_id == "f-123"
    assert not h.is_active  # truth now lives in the Finding, not the hypothesis
    assert h.id not in {o.id for o in wm.open_hypotheses()}


# --- planner query API ----------------------------------------------------------


def test_open_hypotheses_ranked_by_confidence() -> None:
    wm = _wm()
    low = wm.add_hypothesis(subject="a", kind="cve", title="low", prior=0.2)
    high = wm.add_hypothesis(subject="b", kind="cve", title="high", prior=0.8)
    mid = wm.add_hypothesis(subject="c", kind="cve", title="mid", prior=0.5)
    ranked = wm.open_hypotheses()
    assert [h.id for h in ranked] == [high.id, mid.id, low.id]
    assert [h.id for h in wm.open_hypotheses(limit=1)] == [high.id]


def test_reachable_assets_uses_graph_not_asset_field() -> None:
    store = KnowledgeStore("eng-1")
    reachable = Asset(address="10.5.0.10", engagement_id="eng-1",
                      services=(Service(port=80),))
    internal = Asset(address="10.6.0.5", engagement_id="eng-1")
    store.add_asset(reachable, reachable_from_entry=True)
    store.add_asset(internal, reachable_from_entry=False)
    wm = _wm(store)
    addrs = {a.address for a in wm.reachable_assets()}
    assert addrs == {"10.5.0.10"}  # graph reachability, despite Asset.reachable=False


def test_reachable_assets_empty_without_store() -> None:
    assert _wm().reachable_assets() == []


def test_summary_counts() -> None:
    wm = _wm()
    wm.add_hypothesis(subject="a", kind="cve", title="one")
    h2 = wm.add_hypothesis(subject="b", kind="cve", title="two")
    wm.refute(h2.id, "nope")
    summary = wm.summary()
    assert summary["hypotheses"] == 2
    assert summary["hypotheses_active"] == 1
    assert summary["hypotheses_refuted"] == 1
