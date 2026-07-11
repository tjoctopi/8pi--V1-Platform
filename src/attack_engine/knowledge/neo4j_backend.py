"""Neo4j attack-graph backend (spec §9 Sprint 3).

A durable, cross-process implementation of the
:class:`~attack_engine.knowledge.graph_backend.GraphBackend` protocol for
multi-engagement deployments. Nodes carry an ``engagement`` property so one
engagement's graph is isolated from another's within a shared database. The
``neo4j`` driver is an optional dependency; importing this module without it is
fine — construction is what raises. The driver is injectable so the Cypher logic
is unit-testable against a recording fake without a live server.
"""

from __future__ import annotations

from typing import Any

from ..schemas.findings import Asset, Service

ENTRY_ID = "__entry__"


class Neo4jGraphBackend:
    """Attack graph stored in Neo4j. One graph per (database, engagement)."""

    def __init__(
        self,
        *,
        driver: Any = None,
        url: str | None = None,
        user: str | None = None,
        password: str | None = None,
        engagement_id: str = "default",
        database: str | None = None,
    ) -> None:
        if driver is None:
            try:
                from neo4j import GraphDatabase
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError(
                    "the 'neo4j' extra is not installed; "
                    "install attack-engine[neo4j] to use Neo4jGraphBackend"
                ) from exc
            auth = (user, password) if user is not None and password is not None else None
            driver = GraphDatabase.driver(url or "bolt://localhost:7687", auth=auth)
        self._driver: Any = driver
        self._eng = engagement_id
        self._database = database
        self._ensure_entry()

    # --- session helpers ------------------------------------------------------

    def _run(self, query: str, **params: Any) -> list[Any]:
        params.setdefault("eng", self._eng)
        with self._driver.session(database=self._database) as session:
            return list(session.run(query, **params))

    def _run_single(self, query: str, **params: Any) -> Any:
        params.setdefault("eng", self._eng)
        with self._driver.session(database=self._database) as session:
            return session.run(query, **params).single()

    def _ensure_entry(self) -> None:
        self._run(
            "MERGE (n:Node {id: $id, engagement: $eng}) SET n.kind = 'entry'",
            id=ENTRY_ID,
        )

    # --- construction ---------------------------------------------------------

    def add_asset(self, asset: Asset, *, reachable_from_entry: bool = True) -> str:
        self._run(
            """
            MERGE (a:Node {id: $id, engagement: $eng})
            SET a.kind = 'asset', a.address = $address
            """,
            id=asset.id, address=asset.address,
        )
        if reachable_from_entry:
            self.add_edge(ENTRY_ID, asset.id, kind="reaches")
        for svc in asset.services:
            self.add_service(asset.id, svc)
        return asset.id

    def add_service(self, asset_id: str, service: Service) -> str:
        svc_id = f"{asset_id}:{service.port}/{service.protocol}"
        self._run(
            """
            MATCH (a:Node {id: $asset_id, engagement: $eng})
            MERGE (s:Node {id: $sid, engagement: $eng})
            SET s.kind = 'service', s.port = $port, s.protocol = $proto,
                s.product = $product, s.version = $version
            MERGE (a)-[:EDGE {kind: 'exposes'}]->(s)
            """,
            asset_id=asset_id, sid=svc_id, port=service.port, proto=service.protocol,
            product=service.product, version=service.version,
        )
        return svc_id

    def add_edge(self, src: str, dst: str, **attrs: object) -> None:
        self._run(
            """
            MATCH (a:Node {id: $src, engagement: $eng})
            MATCH (b:Node {id: $dst, engagement: $eng})
            MERGE (a)-[r:EDGE]->(b)
            SET r.kind = $kind
            """,
            src=src, dst=dst, kind=str(attrs.get("kind", "reaches")),
        )

    # --- queries --------------------------------------------------------------

    def has_node(self, node_id: str) -> bool:
        rec = self._run_single(
            "RETURN EXISTS((:Node {id: $id, engagement: $eng})) AS present", id=node_id
        )
        return bool(rec["present"]) if rec else False

    def node_data(self, node_id: str) -> dict[str, object]:
        rec = self._run_single(
            "MATCH (n:Node {id: $id, engagement: $eng}) RETURN properties(n) AS props",
            id=node_id,
        )
        if rec is None:
            from ..errors import UnknownNodeError

            raise UnknownNodeError(node_id)
        props: dict[str, object] = dict(rec["props"])
        # Normalise 'kind' → 'node_type' to match the NetworkX backend's shape.
        if "kind" in props:
            props["node_type"] = props.pop("kind")
        return props

    def is_reachable(self, node_id: str) -> bool:
        if node_id == ENTRY_ID:
            return True
        rec = self._run_single(
            """
            MATCH (e:Node {id: $entry, engagement: $eng})
            MATCH (n:Node {id: $id, engagement: $eng})
            RETURN EXISTS((e)-[:EDGE*1..]->(n)) AS reachable
            """,
            entry=ENTRY_ID, id=node_id,
        )
        return bool(rec["reachable"]) if rec else False

    def reachable_assets(self) -> set[str]:
        rows = self._run(
            """
            MATCH (e:Node {id: $entry, engagement: $eng})-[:EDGE*1..]->(a:Node)
            WHERE a.kind = 'asset'
            RETURN DISTINCT a.id AS id
            """,
            entry=ENTRY_ID,
        )
        return {r["id"] for r in rows}

    def shortest_path(self, dst: str, src: str = ENTRY_ID) -> list[str] | None:
        rec = self._run_single(
            """
            MATCH (a:Node {id: $src, engagement: $eng}),
                  (b:Node {id: $dst, engagement: $eng})
            MATCH p = shortestPath((a)-[:EDGE*]->(b))
            RETURN [x IN nodes(p) | x.id] AS path
            """,
            src=src, dst=dst,
        )
        if rec is None or rec["path"] is None:
            return None
        return list(rec["path"])

    def asset_ids(self) -> list[str]:
        rows = self._run(
            "MATCH (a:Node {engagement: $eng}) WHERE a.kind = 'asset' RETURN a.id AS id"
        )
        return [r["id"] for r in rows]

    def service_ids(self, asset_id: str | None = None) -> list[str]:
        rows = self._run(
            "MATCH (s:Node {engagement: $eng}) WHERE s.kind = 'service' RETURN s.id AS id"
        )
        ids = [r["id"] for r in rows]
        if asset_id is not None:
            ids = [i for i in ids if i.startswith(f"{asset_id}:")]
        return ids

    def stats(self) -> dict[str, int]:
        rows = self._run(
            "MATCH (n:Node {engagement: $eng}) RETURN n.kind AS kind, count(*) AS c"
        )
        by_kind = {r["kind"]: int(r["c"]) for r in rows}
        edges = self._run_single(
            "MATCH (:Node {engagement: $eng})-[r:EDGE]->() RETURN count(r) AS c"
        )
        return {
            "nodes": sum(by_kind.values()),
            "edges": int(edges["c"]) if edges else 0,
            "assets": by_kind.get("asset", 0),
            "services": by_kind.get("service", 0),
        }

    def close(self) -> None:
        self._driver.close()
