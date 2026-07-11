"""Privilege-aware attack graph — "the attacker's brain" (kill-chain diagram).

Where the recon :class:`~attack_engine.knowledge.graph.AttackGraph` models the
*surface* (assets + services), this models *positions*: a node is a
``(host, privilege)`` state and an edge is an exploit/technique that moves the
attacker from one state to another at some cost. It grows with every confirmed
foothold, and the planner asks it for the cheapest path from the entry position
to the goal — Dijkstra/A* over exploit edges.

Nothing here executes anything; it is pure planning state.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field

ENTRY = ("__entry__", "none")


@dataclass(frozen=True)
class Position:
    """An attacker position: a privilege level on a host."""

    host: str
    privilege: str  # "none" | "user" | "root" | "admin" | "domain_admin"

    def key(self) -> tuple[str, str]:
        return (self.host, self.privilege)

    def label(self) -> str:
        return f"{self.host}/{self.privilege}"


@dataclass(frozen=True)
class ExploitEdge:
    """A technique that advances the attacker between two positions."""

    src: tuple[str, str]
    dst: tuple[str, str]
    technique: str          # MITRE ATT&CK id, e.g. "T1190"
    name: str               # human label, e.g. "Apache path traversal → shell"
    cost: float = 1.0       # lower = cheaper/more reliable
    finding_id: str | None = None


@dataclass
class PrivilegeGraph:
    """Weighted directed graph of attacker positions and exploit transitions."""

    _adj: dict[tuple[str, str], list[ExploitEdge]] = field(default_factory=dict)
    _nodes: set[tuple[str, str]] = field(default_factory=set)
    goal: tuple[str, str] | None = None

    def __post_init__(self) -> None:
        self.add_position(Position(*ENTRY))

    def add_position(self, position: Position) -> None:
        self._nodes.add(position.key())
        self._adj.setdefault(position.key(), [])

    def add_exploit(self, edge: ExploitEdge) -> None:
        self.add_position(Position(*edge.src))
        self.add_position(Position(*edge.dst))
        self._adj[edge.src].append(edge)

    def set_goal(self, host: str, privilege: str) -> None:
        self.goal = (host, privilege)
        self.add_position(Position(host, privilege))

    def positions(self) -> set[tuple[str, str]]:
        return set(self._nodes)

    def cheapest_path(
        self, goal: tuple[str, str] | None = None, start: tuple[str, str] = ENTRY
    ) -> list[ExploitEdge] | None:
        """Cheapest exploit chain ``start → goal`` (Dijkstra), or None.

        Returns the ordered list of exploit edges to traverse; an empty list
        means start already satisfies the goal.
        """

        target = goal or self.goal
        if target is None or target not in self._nodes or start not in self._nodes:
            return None
        if start == target:
            return []

        dist: dict[tuple[str, str], float] = {start: 0.0}
        prev: dict[tuple[str, str], ExploitEdge] = {}
        pq: list[tuple[float, int, tuple[str, str]]] = [(0.0, 0, start)]
        counter = 1
        visited: set[tuple[str, str]] = set()

        while pq:
            d, _, node = heapq.heappop(pq)
            if node in visited:
                continue
            visited.add(node)
            if node == target:
                break
            for edge in self._adj.get(node, []):
                nd = d + edge.cost
                if nd < dist.get(edge.dst, float("inf")):
                    dist[edge.dst] = nd
                    prev[edge.dst] = edge
                    heapq.heappush(pq, (nd, counter, edge.dst))
                    counter += 1

        if target not in prev and target != start:
            return None
        # Reconstruct.
        chain: list[ExploitEdge] = []
        cur = target
        while cur != start:
            edge = prev[cur]
            chain.append(edge)
            cur = edge.src
        chain.reverse()
        return chain

    def stats(self) -> dict[str, int]:
        return {
            "positions": len(self._nodes),
            "exploit_edges": sum(len(v) for v in self._adj.values()),
        }
