"""Attack-path / kill-chain construction (spec §3 — the *coordinated* attack).

Turns confirmed, exploitable footholds into ordered attack chains over the
attack graph: entry → (reachable hops) → target, annotated with the technique
that gets you there and a reachability-gated exploitability score. This is what
makes it a coordinated attack rather than a bag of findings — it shows the
shortest actually-reachable route to each compromised asset, ranked by risk.
"""

from __future__ import annotations

from collections import defaultdict

from ..knowledge.store import KnowledgeStore
from ..schemas.common import StrictModel
from ..schemas.findings import Finding, FindingState, Priority


class AttackChain(StrictModel):
    target: str
    reachable: bool
    hops: int
    #: Readable node sequence from entry to the target.
    path: list[str]
    #: MITRE techniques / finding types exploited to reach/own the target.
    techniques: list[str]
    finding_types: list[str]
    #: Reachability-gated chain score (0 when the target is unreachable).
    score: float


def _label(store: KnowledgeStore, node_id: str) -> str:
    if node_id == "__entry__":
        return "entry"
    asset = store.get_asset(node_id)
    if asset is not None:
        return asset.address
    return node_id  # service nodes keep their "asset:port/proto" id


def build_attack_paths(store: KnowledgeStore) -> list[AttackChain]:
    """Build reachability-ranked attack chains from confirmed findings."""

    graph = store.graph
    by_asset: dict[str, list[Finding]] = defaultdict(list)
    for f in store.findings(FindingState.CONFIRMED):
        # Only actionable footholds (an exploitable, non-informational vuln).
        if f.priority is Priority.INFORMATIONAL:
            continue
        by_asset[f.asset].append(f)

    chains: list[AttackChain] = []
    for asset in store.assets():
        vulns = by_asset.get(asset.address) or by_asset.get(asset.id) or []
        if not vulns:
            continue
        reachable = graph.is_reachable(asset.id)
        node_path = graph.shortest_path(asset.id) if reachable else None
        path = [_label(store, n) for n in node_path] if node_path else [asset.address]
        best_prob = max((f.exploit_prob or 0.0) for f in vulns)
        score = round(best_prob if reachable else 0.0, 4)
        techniques = sorted(
            {str(f.metadata.get("technique") or f.type) for f in vulns}
        )
        chains.append(
            AttackChain(
                target=asset.address,
                reachable=reachable,
                hops=max(0, len(node_path) - 1) if node_path else 0,
                path=path,
                techniques=techniques,
                finding_types=sorted({f.type for f in vulns}),
                score=score,
            )
        )
    chains.sort(key=lambda c: -c.score)
    return chains
