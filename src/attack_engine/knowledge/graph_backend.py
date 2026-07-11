"""Graph backend protocol (spec §9 Sprint 3 — "move Knowledge Store to Neo4j").

The attack graph is used through this narrow structural interface so the storage
engine is swappable: the in-process NetworkX
:class:`~attack_engine.knowledge.graph.AttackGraph` is the default (and what the
test suite exercises), while :class:`~attack_engine.knowledge.neo4j_backend.Neo4jGraphBackend`
provides a durable, cross-process store for multi-engagement deployments —
behind the *same* interface, so nothing above the knowledge store changes.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..schemas.findings import Asset, Service


@runtime_checkable
class GraphBackend(Protocol):
    """The attack-graph operations the Knowledge Store depends on."""

    def add_asset(self, asset: Asset, *, reachable_from_entry: bool = True) -> str: ...
    def add_service(self, asset_id: str, service: Service) -> str: ...
    def add_edge(self, src: str, dst: str, **attrs: object) -> None: ...
    def has_node(self, node_id: str) -> bool: ...
    def node_data(self, node_id: str) -> dict[str, object]: ...
    def reachable_assets(self) -> set[str]: ...
    def is_reachable(self, node_id: str) -> bool: ...
    def shortest_path(self, dst: str, src: str = ...) -> list[str] | None: ...
    def asset_ids(self) -> list[str]: ...
    def service_ids(self, asset_id: str | None = None) -> list[str]: ...
    def stats(self) -> dict[str, int]: ...


def build_graph_backend(settings: object | None = None) -> GraphBackend:
    """Construct the configured graph backend (NetworkX default; Neo4j optional)."""

    from ..config import GraphBackendKind, Settings, get_settings
    from .graph import AttackGraph

    s: Settings = settings or get_settings()  # type: ignore[assignment]
    if s.graph_backend is GraphBackendKind.NETWORKX:
        return AttackGraph()
    if s.graph_backend is GraphBackendKind.NEO4J:
        from .neo4j_backend import Neo4jGraphBackend

        return Neo4jGraphBackend(
            url=s.neo4j_url,
            user=s.neo4j_user,
            password=s.neo4j_password.get_secret_value() if s.neo4j_password else None,
            engagement_id=s.neo4j_database,
        )
    raise NotImplementedError(f"graph backend {s.graph_backend!r} unavailable")
