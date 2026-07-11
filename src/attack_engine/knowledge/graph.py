"""Attack graph over NetworkX (spec §5 — reachability, path search).

The graph is the backbone of accuracy-by-reachability: we prioritise findings
by whether a target is actually reachable from the attacker's entry node, not by
raw CVSS. Nodes are the entry point, assets, and their services; directed edges
model "can reach". ``reachable_assets`` is the descendant set of the entry node;
``shortest_path`` powers the Orchestrator's cheapest-path DAG planning in a
later sprint.

NetworkX in-process is the Sprint 0 store; the same API is what a Neo4j-backed
implementation will satisfy in Sprint 3.
"""

from __future__ import annotations

from enum import Enum

import networkx as nx

from ..errors import UnknownNodeError
from ..schemas.findings import Asset, Service

ENTRY_NODE = "__entry__"


class NodeType(str, Enum):
    ENTRY = "entry"
    ASSET = "asset"
    SERVICE = "service"


class AttackGraph:
    """A directed reachability graph of one engagement's attack surface."""

    def __init__(self) -> None:
        self._g = nx.DiGraph()
        self._g.add_node(ENTRY_NODE, node_type=NodeType.ENTRY.value)

    # --- construction ---------------------------------------------------------

    def add_asset(self, asset: Asset, *, reachable_from_entry: bool = True) -> str:
        """Add/refresh an asset node. Returns its node id.

        A freshly *discovered* asset is reachable from entry by definition (we
        reached it to scan it); callers can override for assets inferred but not
        directly probed.
        """

        node_id = asset.id
        self._g.add_node(
            node_id,
            node_type=NodeType.ASSET.value,
            address=asset.address,
            hostnames=list(asset.hostnames),
        )
        if reachable_from_entry:
            self._g.add_edge(ENTRY_NODE, node_id)
        for svc in asset.services:
            self.add_service(node_id, svc)
        return node_id

    def add_service(self, asset_id: str, service: Service) -> str:
        if asset_id not in self._g:
            raise UnknownNodeError(f"asset {asset_id!r} not in graph")
        svc_id = f"{asset_id}:{service.port}/{service.protocol}"
        self._g.add_node(
            svc_id,
            node_type=NodeType.SERVICE.value,
            port=service.port,
            protocol=service.protocol,
            product=service.product,
            version=service.version,
        )
        self._g.add_edge(asset_id, svc_id)
        return svc_id

    def add_edge(self, src: str, dst: str, **attrs: object) -> None:
        """Add a reachability edge (e.g. lateral movement pivot)."""

        for node in (src, dst):
            if node not in self._g:
                raise UnknownNodeError(f"node {node!r} not in graph")
        self._g.add_edge(src, dst, **attrs)

    # --- queries --------------------------------------------------------------

    def has_node(self, node_id: str) -> bool:
        return node_id in self._g

    def node_data(self, node_id: str) -> dict[str, object]:
        if node_id not in self._g:
            raise UnknownNodeError(node_id)
        return dict(self._g.nodes[node_id])

    def reachable_assets(self) -> set[str]:
        """Asset node ids reachable from the entry node."""

        reachable = nx.descendants(self._g, ENTRY_NODE)
        return {
            n for n in reachable
            if self._g.nodes[n].get("node_type") == NodeType.ASSET.value
        }

    def is_reachable(self, node_id: str) -> bool:
        if node_id not in self._g or node_id == ENTRY_NODE:
            return node_id == ENTRY_NODE
        return bool(nx.has_path(self._g, ENTRY_NODE, node_id))

    def shortest_path(self, dst: str, src: str = ENTRY_NODE) -> list[str] | None:
        """Cheapest reachability path ``src -> dst``, or ``None`` if unreachable."""

        if src not in self._g or dst not in self._g:
            raise UnknownNodeError(f"path endpoints must exist: {src!r} -> {dst!r}")
        try:
            return nx.shortest_path(self._g, src, dst)  # type: ignore[no-any-return]
        except nx.NetworkXNoPath:
            return None

    def asset_ids(self) -> list[str]:
        return [
            n for n, d in self._g.nodes(data=True)
            if d.get("node_type") == NodeType.ASSET.value
        ]

    def service_ids(self, asset_id: str | None = None) -> list[str]:
        out = []
        for n, d in self._g.nodes(data=True):
            if d.get("node_type") != NodeType.SERVICE.value:
                continue
            if asset_id is None or n.startswith(f"{asset_id}:"):
                out.append(n)
        return out

    def stats(self) -> dict[str, int]:
        types: dict[str, int] = {}
        for _n, d in self._g.nodes(data=True):
            t = str(d.get("node_type", "unknown"))
            types[t] = types.get(t, 0) + 1
        return {
            "nodes": self._g.number_of_nodes(),
            "edges": self._g.number_of_edges(),
            "assets": types.get(NodeType.ASSET.value, 0),
            "services": types.get(NodeType.SERVICE.value, 0),
        }
