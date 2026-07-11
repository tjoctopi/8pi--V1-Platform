"""Union-find dedup tests."""

from __future__ import annotations

from attack_engine.knowledge.dedup import DedupIndex
from attack_engine.schemas.findings import Finding


def mkf(asset: str, ftype: str, eng: str = "eng-1") -> Finding:
    return Finding(engagement_id=eng, asset=asset, type=ftype)


def test_same_asset_and_type_cluster_together() -> None:
    idx = DedupIndex()
    f1 = mkf("10.0.4.12", "CVE-2021-41773")
    f2 = mkf("10.0.4.12", "CVE-2021-41773")
    rep1 = idx.add(f1)
    rep2 = idx.add(f2)
    assert rep1 == f1.id
    assert rep2 == f1.id  # f2 folds into f1's cluster
    assert idx.cluster_count() == 1


def test_type_normalization_is_case_insensitive() -> None:
    idx = DedupIndex()
    a = idx.add(mkf("10.0.4.12", "cve-2021-41773"))
    b = idx.add(mkf("10.0.4.12", "CVE-2021-41773"))
    assert a == b


def test_different_assets_do_not_cluster() -> None:
    idx = DedupIndex()
    idx.add(mkf("10.0.4.12", "open-port"))
    idx.add(mkf("10.0.4.13", "open-port"))
    assert idx.cluster_count() == 2


def test_different_engagements_do_not_cluster() -> None:
    idx = DedupIndex()
    idx.add(mkf("10.0.4.12", "open-port", eng="eng-1"))
    idx.add(mkf("10.0.4.12", "open-port", eng="eng-2"))
    assert idx.cluster_count() == 2


def test_distinct_injection_points_do_not_cluster() -> None:
    # Two SQLi on the same host but DIFFERENT injection points are different
    # vulnerabilities — collapsing them would hide a real breach vector.
    idx = DedupIndex()
    a = Finding(engagement_id="e", asset="10.5.0.10", type="sqli-boolean-blind",
                metadata={"path": "/rest/products/search", "param": "q"})
    b = Finding(engagement_id="e", asset="10.5.0.10", type="sqli-boolean-blind",
                metadata={"path": "/user", "param": "id"})
    idx.add(a)
    idx.add(b)
    assert idx.cluster_count() == 2


def test_same_injection_point_from_two_tools_clusters() -> None:
    # The SAME point reported twice IS a duplicate and must fold together.
    idx = DedupIndex()
    md = {"path": "/rest/products/search", "param": "q"}
    a = Finding(engagement_id="e", asset="10.5.0.10", type="sqli-boolean-blind", metadata=md)
    b = Finding(engagement_id="e", asset="10.5.0.10", type="sqli-boolean-blind", metadata=dict(md))
    assert idx.add(a) == a.id
    assert idx.add(b) == a.id
    assert idx.cluster_count() == 1


def test_is_duplicate() -> None:
    idx = DedupIndex()
    f = mkf("10.0.4.12", "open-port")
    assert not idx.is_duplicate(f)
    idx.add(f)
    assert idx.is_duplicate(mkf("10.0.4.12", "open-port"))


def test_cluster_members_grouping() -> None:
    idx = DedupIndex()
    f1 = mkf("10.0.4.12", "x")
    f2 = mkf("10.0.4.12", "x")
    f3 = mkf("10.0.4.99", "y")
    for f in (f1, f2, f3):
        idx.add(f)
    groups = idx.cluster_members([f1.id, f2.id, f3.id])
    sizes = sorted(len(v) for v in groups.values())
    assert sizes == [1, 2]
