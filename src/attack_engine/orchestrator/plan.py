"""Attack DAG planning (spec §3 step 1, §5 "deterministic planner + LLM").

The plan is deterministic and explainable: a directed acyclic graph of phases
whose edges encode ordering, topologically sorted into an execution order. Target
prioritisation uses cheapest-path search over the attack graph — reachable
targets first, ordered by distance from the entry node — so the engine spends
effort where it can actually reach. The LLM interprets intent; the *logic* is
this graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from ..knowledge.graph_backend import GraphBackend


@dataclass(frozen=True)
class Phase:
    name: str
    description: str
    gated: bool = False


#: Canonical purple-team loop phases and their dependencies (DAG edges).
_PHASES: dict[str, Phase] = {
    "recon": Phase("recon", "Discover hosts, services, web surface"),
    "verify_services": Phase("verify_services", "Confirm service/version observations"),
    "web": Phase("web", "Enumerate web surface + OWASP; surface SQLi candidates"),
    "exploit_confirm": Phase("exploit_confirm", "Confirm candidates (no extraction)", gated=True),
    "verify_vulns": Phase("verify_vulns", "Independently confirm exploit candidates"),
    "correlate": Phase("correlate", "Map services to CVE/KEV; score exploitability"),
    "convert": Phase("convert", "Propose remediations (propose-only)"),
    "report": Phase("report", "Generate the engagement report"),
}

_DEPENDENCIES: list[tuple[str, str]] = [
    ("recon", "verify_services"),
    ("recon", "web"),
    ("verify_services", "correlate"),
    ("web", "exploit_confirm"),
    ("exploit_confirm", "verify_vulns"),
    ("verify_vulns", "correlate"),
    ("correlate", "convert"),
    ("convert", "report"),
]


@dataclass
class AttackPlan:
    goal: str
    phases: list[Phase]
    prioritized_targets: list[str] = field(default_factory=list)

    def phase_names(self) -> list[str]:
        return [p.name for p in self.phases]


def _ordered_phases() -> list[Phase]:
    g: nx.DiGraph = nx.DiGraph()
    g.add_nodes_from(_PHASES)
    g.add_edges_from(_DEPENDENCIES)
    if not nx.is_directed_acyclic_graph(g):  # pragma: no cover - static graph
        raise ValueError("phase graph is not a DAG")
    return [_PHASES[name] for name in nx.topological_sort(g)]


def prioritize_targets(targets: list[str], graph: GraphBackend) -> list[str]:
    """Reachable-from-entry targets first, ordered by graph distance.

    Targets not yet in the graph (e.g. before recon) keep their input order and
    sort after known-reachable ones.
    """

    def sort_key(target: str) -> tuple[int, int, int]:
        asset = next(
            (a for a in graph.asset_ids() if graph.node_data(a).get("address") == target),
            None,
        )
        if asset is None:
            return (2, 0, targets.index(target))  # unknown → last, stable
        if not graph.is_reachable(asset):
            return (1, 0, targets.index(target))  # known but unreachable
        path = graph.shortest_path(asset)
        distance = len(path) if path else 1_000_000
        return (0, distance, targets.index(target))

    return sorted(targets, key=sort_key)


def build_plan(goal: str, targets: list[str], graph: GraphBackend) -> AttackPlan:
    """Produce a topologically-ordered phase plan + prioritised targets."""

    return AttackPlan(
        goal=goal,
        phases=_ordered_phases(),
        prioritized_targets=prioritize_targets(targets, graph),
    )
