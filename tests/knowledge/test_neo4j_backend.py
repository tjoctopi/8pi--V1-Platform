"""Neo4j graph backend tests via a recording fake driver (no server needed).

These verify the backend issues sensible Cypher and correctly interprets driver
results — the logic that would otherwise only be exercised against a live Neo4j.
A live-server integration test is marked separately and skipped by default.
"""

from __future__ import annotations

from typing import Any

from attack_engine.knowledge.graph import AttackGraph
from attack_engine.knowledge.graph_backend import GraphBackend
from attack_engine.knowledge.neo4j_backend import Neo4jGraphBackend
from attack_engine.schemas.findings import Asset, Service


class FakeResult:
    def __init__(self, records: list[dict[str, Any]]) -> None:
        self._records = records

    def __iter__(self):
        return iter(self._records)

    def single(self) -> dict[str, Any] | None:
        return self._records[0] if self._records else None


class FakeSession:
    def __init__(self, driver: FakeDriver) -> None:
        self._driver = driver

    def __enter__(self) -> FakeSession:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def run(self, query: str, **params: Any) -> FakeResult:
        self._driver.queries.append((query, params))
        for substring, records in self._driver.responses.items():
            if substring in query:
                return FakeResult(list(records))
        return FakeResult([])


class FakeDriver:
    """Records every query; returns programmed records by query-substring match."""

    def __init__(self, responses: dict[str, list[dict[str, Any]]] | None = None) -> None:
        self.queries: list[tuple[str, dict[str, Any]]] = []
        self.responses = responses or {}

    def session(self, database: str | None = None) -> FakeSession:
        return FakeSession(self)

    def close(self) -> None:
        pass


def _backend(responses: dict[str, list[dict[str, Any]]] | None = None) -> Neo4jGraphBackend:
    return Neo4jGraphBackend(driver=FakeDriver(responses or {}), engagement_id="eng-1")


def test_satisfies_graph_backend_protocol() -> None:
    assert isinstance(_backend(), GraphBackend)
    assert isinstance(AttackGraph(), GraphBackend)


def test_constructor_ensures_entry_node() -> None:
    driver = FakeDriver()
    Neo4jGraphBackend(driver=driver, engagement_id="eng-1")
    assert any("MERGE (n:Node {id: $id" in q for q, _ in driver.queries)
    # engagement scoping is threaded into params on every query.
    assert all(p.get("eng") == "eng-1" for _q, p in driver.queries)


def test_add_asset_merges_asset_and_entry_edge() -> None:
    driver = FakeDriver()
    backend = Neo4jGraphBackend(driver=driver, engagement_id="eng-1")
    backend.add_asset(Asset(id="a-1", address="10.5.0.10", engagement_id="eng-1",
                            services=(Service(port=80),)))
    joined = "\n".join(q for q, _ in driver.queries)
    assert "a.kind = 'asset'" in joined
    assert "MERGE (a)-[r:EDGE]" in joined  # entry→asset reachability edge
    assert "s.kind = 'service'" in joined  # service node created


def test_is_reachable_parses_driver_result() -> None:
    backend = _backend({"EXISTS((e)-[:EDGE*1..]->(n))": [{"reachable": True}]})
    assert backend.is_reachable("a-1") is True
    assert backend.is_reachable("__entry__") is True  # entry always reachable


def test_is_reachable_false_when_no_path() -> None:
    backend = _backend({"EXISTS((e)-[:EDGE*1..]->(n))": [{"reachable": False}]})
    assert backend.is_reachable("a-2") is False


def test_shortest_path_parses_node_ids() -> None:
    backend = _backend({"shortestPath": [{"path": ["__entry__", "a-1", "a-1:80/tcp"]}]})
    assert backend.shortest_path("a-1:80/tcp") == ["__entry__", "a-1", "a-1:80/tcp"]


def test_shortest_path_none_when_unreachable() -> None:
    backend = _backend({"shortestPath": [{"path": None}]})
    assert backend.shortest_path("a-9") is None


def test_reachable_assets_collects_ids() -> None:
    backend = _backend({"WHERE a.kind = 'asset'": [{"id": "a-1"}, {"id": "a-2"}]})
    assert backend.reachable_assets() == {"a-1", "a-2"}


def test_node_data_normalises_kind_to_node_type() -> None:
    backend = _backend(
        {"RETURN properties(n)": [{"props": {"id": "a-1", "kind": "asset", "address": "10.5.0.10"}}]}
    )
    data = backend.node_data("a-1")
    assert data["node_type"] == "asset"
    assert "kind" not in data


def test_stats_aggregates_kinds_and_edges() -> None:
    backend = _backend({
        "RETURN n.kind AS kind": [{"kind": "asset", "c": 1}, {"kind": "service", "c": 2}],
        "count(r) AS c": [{"c": 3}],
    })
    stats = backend.stats()
    assert stats == {"nodes": 3, "edges": 3, "assets": 1, "services": 2}
