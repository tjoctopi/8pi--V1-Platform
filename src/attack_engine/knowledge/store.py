"""Knowledge Store — the blackboard (spec §2, §5).

The single source of shared truth for an engagement: the attack graph, the
asset inventory, and every finding with its propose→verify→confirm lifecycle.
Agents never call each other; they read and write here, and every mutation
emits a blackboard event so the Orchestrator and Blue Sentry can react.

Two accuracy mechanics live here:

* **De-duplication** — union-find collapses the same finding reported by
  multiple tools, merging their evidence instead of double-counting.
* **Reachability** — a finding's ``reachable`` flag is derived from the attack
  graph, so scoring can prioritise reachable-from-entry issues (a Sprint 1
  correlator consumes this).
"""

from __future__ import annotations

import threading

from ..eventbus.base import EventPublisher
from ..logging import get_logger
from ..schemas.events import Event, EventType
from ..schemas.findings import Asset, Finding, FindingState, Priority, Service
from ..schemas.remediation import Remediation
from .dedup import DedupIndex
from .graph import AttackGraph
from .graph_backend import GraphBackend

_log = get_logger("knowledge.store")


def _merge_services(
    existing: tuple[Service, ...], incoming: tuple[Service, ...]
) -> tuple[tuple[Service, ...], list[Service]]:
    """Merge service tuples keyed by (port, protocol).

    Returns (merged, newly_added). A richer record (more product/version info)
    supersedes a sparser one for the same port.
    """

    by_key: dict[tuple[int, str], Service] = {(s.port, s.protocol): s for s in existing}
    added: list[Service] = []
    for svc in incoming:
        key = (svc.port, svc.protocol)
        prev = by_key.get(key)
        if prev is None:
            by_key[key] = svc
            added.append(svc)
        else:
            # Prefer the record carrying more identifying detail.
            prev_detail = sum(x is not None for x in (prev.product, prev.version))
            new_detail = sum(x is not None for x in (svc.product, svc.version))
            if new_detail > prev_detail:
                by_key[key] = svc
    merged = tuple(sorted(by_key.values(), key=lambda s: (s.port, s.protocol)))
    return merged, added


class KnowledgeStore:
    """Per-engagement shared state. Thread-safe for concurrent agents."""

    def __init__(
        self,
        engagement_id: str,
        event_bus: EventPublisher | None = None,
        *,
        graph: GraphBackend | None = None,
    ) -> None:
        self.engagement_id = engagement_id
        self._bus = event_bus
        self._graph: GraphBackend = graph if graph is not None else AttackGraph()
        self._dedup = DedupIndex()
        self._assets_by_address: dict[str, Asset] = {}
        self._assets_by_id: dict[str, Asset] = {}
        self._findings: dict[str, Finding] = {}
        self._remediations: dict[str, Remediation] = {}
        self._lock = threading.RLock()

    @property
    def graph(self) -> GraphBackend:
        return self._graph

    def _emit(self, event: EventType, **kwargs: object) -> None:
        if self._bus is None:
            return
        self._bus.publish(Event(event=event, engagement_id=self.engagement_id, **kwargs))

    # --- assets ---------------------------------------------------------------

    def add_asset(
        self,
        asset: Asset,
        *,
        emitted_by: str = "unknown",
        reachable_from_entry: bool = True,
    ) -> Asset:
        """Ingest an asset, merging with any prior record for the same address.

        ``reachable_from_entry`` is ``False`` for an internal-only host inferred
        but not directly reached from the entry point (e.g. seen behind a pivot)
        — it lands in the graph without an entry edge, so the correlator
        deprioritises its findings automatically.

        Emits ``asset.discovered`` the first time an address is seen and
        ``service.discovered`` for each newly observed service.
        """

        if asset.engagement_id != self.engagement_id:
            raise ValueError(
                f"asset engagement {asset.engagement_id!r} != store {self.engagement_id!r}"
            )
        with self._lock:
            existing = self._assets_by_address.get(asset.address)
            if existing is None:
                self._assets_by_address[asset.address] = asset
                self._assets_by_id[asset.id] = asset
                self._graph.add_asset(asset, reachable_from_entry=reachable_from_entry)
                canonical = asset
                self._emit(
                    EventType.ASSET_DISCOVERED,
                    emitted_by=emitted_by,
                    asset_id=asset.id,
                    payload={"address": asset.address},
                )
                new_services = list(asset.services)
            else:
                merged_services, new_services = _merge_services(
                    existing.services, asset.services
                )
                canonical = existing.model_copy(update={"services": merged_services})
                self._assets_by_address[asset.address] = canonical
                self._assets_by_id[canonical.id] = canonical
                for svc in new_services:
                    self._graph.add_service(canonical.id, svc)

            for svc in new_services:
                self._emit(
                    EventType.SERVICE_DISCOVERED,
                    emitted_by=emitted_by,
                    asset_id=canonical.id,
                    payload={
                        "address": canonical.address,
                        "port": svc.port,
                        "protocol": svc.protocol,
                        "product": svc.product,
                        "version": svc.version,
                    },
                )
            return canonical

    def assets(self) -> list[Asset]:
        with self._lock:
            return list(self._assets_by_address.values())

    def get_asset(self, address_or_id: str) -> Asset | None:
        with self._lock:
            return self._assets_by_address.get(address_or_id) or self._assets_by_id.get(
                address_or_id
            )

    # --- findings -------------------------------------------------------------

    def propose_finding(self, finding: Finding, *, emitted_by: str = "unknown") -> Finding:
        """Register a proposed finding; de-duplicate against prior reports.

        If an equivalent finding already exists, its evidence is merged into the
        representative and that representative is returned (no duplicate stored).
        Otherwise the new finding is stored and ``finding.proposed`` emitted.
        """

        if finding.engagement_id != self.engagement_id:
            raise ValueError("finding engagement mismatch")
        with self._lock:
            rep_id = self._dedup.add(finding)
            if rep_id != finding.id:
                # Duplicate: fold its evidence into the representative.
                rep = self._findings[rep_id]
                merged_evidence = tuple(dict.fromkeys((*rep.evidence, *finding.evidence)))
                rep = rep.model_copy(update={"evidence": merged_evidence})
                self._findings[rep_id] = rep
                _log.debug("finding deduped", finding_id=finding.id, rep=rep_id)
                return rep

            # Derive reachability from the graph if we know the asset.
            reachable = self._reachability_for(finding.asset)
            stored = finding.model_copy(update={"reachable": reachable})
            self._findings[stored.id] = stored
            self._emit(
                EventType.FINDING_PROPOSED,
                emitted_by=emitted_by,
                finding_id=stored.id,
                payload={"type": stored.type, "asset": stored.asset},
            )
            return stored

    def promote_finding(
        self,
        finding_id: str,
        new_state: FindingState,
        *,
        verified_by: str | None = None,
        rejected_reason: str | None = None,
        evidence: tuple[str, ...] = (),
        exploit_prob: float | None = None,
        priority: Priority | None = None,
        emitted_by: str = "verifier",
    ) -> Finding:
        """Advance a finding's state (the only sanctioned path — rule #1)."""

        with self._lock:
            current = self._findings[finding_id]
            promoted = current.promote(
                new_state,
                verified_by=verified_by,
                rejected_reason=rejected_reason,
                evidence=evidence,
                exploit_prob=exploit_prob,
                priority=priority,
            )
            self._findings[finding_id] = promoted
            event_map = {
                FindingState.VERIFIED: EventType.FINDING_VERIFIED,
                FindingState.CONFIRMED: EventType.FINDING_CONFIRMED,
                FindingState.REJECTED: EventType.FINDING_REJECTED,
            }
            evt = event_map.get(new_state)
            if evt is not None:
                self._emit(
                    evt,
                    emitted_by=emitted_by,
                    finding_id=finding_id,
                    payload={"type": promoted.type, "state": new_state.value},
                )
            return promoted

    def _reachability_for(self, asset_ref: str) -> bool:
        asset = self._assets_by_address.get(asset_ref) or self._assets_by_id.get(asset_ref)
        if asset is None:
            return False
        return self._graph.is_reachable(asset.id)

    def get_finding(self, finding_id: str) -> Finding | None:
        with self._lock:
            return self._findings.get(finding_id)

    def findings(self, state: FindingState | None = None) -> list[Finding]:
        with self._lock:
            values = list(self._findings.values())
        if state is None:
            return values
        return [f for f in values if f.state is state]

    # --- remediations ---------------------------------------------------------

    def add_remediation(
        self, remediation: Remediation, *, emitted_by: str = "converter"
    ) -> Remediation:
        """Store a proposed remediation and emit ``remediation.proposed``."""

        if remediation.engagement_id != self.engagement_id:
            raise ValueError("remediation engagement mismatch")
        with self._lock:
            self._remediations[remediation.id] = remediation
        self._emit(
            EventType.REMEDIATION_PROPOSED,
            emitted_by=emitted_by,
            finding_id=remediation.finding_id,
            payload={"remediation_id": remediation.id, "kind": remediation.kind.value},
        )
        return remediation

    def update_remediation(self, remediation: Remediation) -> Remediation:
        with self._lock:
            self._remediations[remediation.id] = remediation
        return remediation

    def remediations(self, finding_id: str | None = None) -> list[Remediation]:
        with self._lock:
            values = list(self._remediations.values())
        if finding_id is None:
            return values
        return [r for r in values if r.finding_id == finding_id]

    def stats(self) -> dict[str, int]:
        with self._lock:
            by_state: dict[str, int] = {}
            for f in self._findings.values():
                by_state[f.state.value] = by_state.get(f.state.value, 0) + 1
            return {
                "assets": len(self._assets_by_address),
                "findings": len(self._findings),
                "finding_clusters": self._dedup.cluster_count(),
                **{f"findings_{k}": v for k, v in by_state.items()},
                **self._graph.stats(),
            }
