"""Lateral movement + campaign chaining (O6).

From the hosts already compromised (confirmed footholds), plan the next hops
toward the objective — combining two views:

* **network lateral** — from a foothold to other in-scope, reachable hosts via
  remote-service exploitation (T1210) / remote services (T1021);
* **identity lateral** — an Active Directory attack path (O5) from an owned
  principal to Domain Admin, each ACL/session hop a lateral step.

The planner produces an ordered, ATT&CK-labelled chain; executing a hop is a
gated/authorized action (metasploit / C2), scope-bound and audited. Frontier
expansion across iterations lives in the campaign runner — as new hosts are
compromised they enter the foothold set and the next plan reaches further.
"""

from __future__ import annotations

from ..ad.graph import ADGraph
from ..knowledge.store import KnowledgeStore
from ..schemas.common import StrictModel
from ..schemas.findings import FindingState, Priority


class LateralHop(StrictModel):
    from_node: str
    to_node: str
    technique: str
    mechanism: str      # "remote-service" | "identity"
    confirmed: bool = False


class LateralPlan(StrictModel):
    objective: str
    reachable: bool
    hops: list[LateralHop] = []

    def to_markdown(self) -> str:
        if not self.hops:
            return f"**Lateral to {self.objective}** — no lateral hop available.\n"
        head = "reaches objective" if self.reachable else "partial"
        lines = [f"**Lateral movement toward {self.objective}** — {head}", ""]
        for i, h in enumerate(self.hops, 1):
            tag = "confirmed" if h.confirmed else "planned"
            lines.append(
                f"  {i}. {h.from_node} →[{h.mechanism} / {h.technique}, {tag}]→ {h.to_node}"
            )
        return "\n".join(lines) + "\n"


class LateralPlanner:
    """Plans lateral movement from confirmed footholds toward an objective."""

    def __init__(self, store: KnowledgeStore) -> None:
        self._store = store

    def _footholds(self) -> set[str]:
        return {
            f.asset for f in self._store.findings(FindingState.CONFIRMED)
            if f.priority is not Priority.INFORMATIONAL
        }

    def plan(
        self,
        objective_host: str,
        *,
        ad_graph: ADGraph | None = None,
        owned_principals: list[str] | None = None,
    ) -> LateralPlan:
        footholds = self._footholds()
        hops: list[LateralHop] = []

        # Network lateral: from each compromised host toward other reachable,
        # in-scope hosts (the objective in particular).
        reachable = {
            a.address for a in self._store.assets()
            if self._store.graph.is_reachable(a.id)
        }
        for fh in sorted(footholds):
            for host in sorted(reachable - footholds):
                if host == objective_host:
                    hops.append(LateralHop(
                        from_node=fh, to_node=host, technique="T1210",
                        mechanism="remote-service"))

        # Identity lateral: an AD path from an owned principal to Domain Admin.
        if ad_graph is not None and owned_principals:
            for path in ad_graph.attack_paths(owned_principals):
                for edge in path.edges:
                    hops.append(LateralHop(
                        from_node=edge.src, to_node=edge.dst,
                        technique=edge.technique, mechanism="identity"))

        objective_reached = (
            objective_host in footholds
            or any(h.to_node == objective_host for h in hops)
            or (ad_graph is not None and bool(owned_principals)
                and bool(ad_graph.attack_paths(owned_principals or [])))
        )
        return LateralPlan(objective=objective_host, reachable=objective_reached, hops=hops)
