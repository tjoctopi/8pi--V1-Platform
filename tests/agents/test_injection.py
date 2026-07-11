"""Injection insertion-point discovery tests."""

from __future__ import annotations

from attack_engine.agents.injection import build_injection_points
from attack_engine.knowledge.store import KnowledgeStore
from attack_engine.schemas.findings import Finding


def _store() -> KnowledgeStore:
    return KnowledgeStore("eng-inj")


def test_catalog_points_present_on_empty_store() -> None:
    points = build_injection_points(_store(), "10.5.0.10", "http", 3000)
    keys = {p.key() for p in points}
    # The generic seed catalog is always available as a fallback.
    assert ("/rest/products/search", "q", "GET") in keys
    assert ("/user", "id", "GET") in keys
    # Scheme/port propagate to every point.
    assert all(p.scheme == "http" and p.port == 3000 for p in points)


def test_harvests_sqli_candidate_leads_first() -> None:
    store = _store()
    store.propose_finding(Finding(
        engagement_id="eng-inj", asset="10.5.0.10", type="sqli-candidate",
        metadata={"scheme": "http", "port": 3000, "path": "/rest/user/find",
                  "param": "email", "base_value": "a@b.c"}))
    points = build_injection_points(store, "10.5.0.10", "http", 3000)
    # Blackboard leads are ranked first (highest signal).
    assert points[0].path == "/rest/user/find" and points[0].param == "email"
    assert points[0].base_value == "a@b.c"


def test_discovered_api_root_is_expanded() -> None:
    store = _store()
    # ffuf discovered the /rest API root.
    store.propose_finding(Finding(
        engagement_id="eng-inj", asset="10.5.0.10", type="web-path:rest",
        title="Discovered /rest"))
    points = build_injection_points(store, "10.5.0.10", "http", 3000)
    keys = {p.key() for p in points}
    # The root is expanded with common REST insertion points.
    assert ("/rest/products/search", "q", "GET") in keys
    assert ("/rest/users", "id", "GET") in keys


def test_dedup_and_limit() -> None:
    store = _store()
    # A candidate that duplicates a catalog point must not appear twice.
    store.propose_finding(Finding(
        engagement_id="eng-inj", asset="10.5.0.10", type="sqli-candidate",
        metadata={"path": "/rest/products/search", "param": "q", "base_value": "x"}))
    points = build_injection_points(store, "10.5.0.10", "http", 3000, limit=5)
    keys = [p.key() for p in points]
    assert len(keys) == len(set(keys))  # no duplicates
    assert len(points) <= 5             # limit respected
    # The candidate (with its own base value) wins over the catalog duplicate.
    search = next(p for p in points if p.path == "/rest/products/search")
    assert search.base_value == "x"
