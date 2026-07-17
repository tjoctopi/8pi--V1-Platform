"""World Model — the fleet's shared, probabilistic belief state (spec §2, brain).

Complements the :class:`~attack_engine.knowledge.store.KnowledgeStore` (the
deterministic record of assets, services and Findings) with the *proposal-space*
layer the reasoning loop plans over: :class:`Hypothesis` objects carried with a
fused confidence and provenance.

    - The **Ideator** writes hypotheses ("this endpoint smells like IDOR").
    - The **loop** reads :meth:`open_hypotheses` — the ranked live leads — to
      decide what to probe next.
    - Tool output arrives as :class:`Observation`\\s; :meth:`observe` fuses each
      into the subject hypothesis (agreement raises confidence, contradiction
      lowers it), using the Bayesian log-odds fusion shared with the verify layer.

Truth never lives here. A hypothesis only ever *proposes*; it graduates into a
Finding (which then runs propose→verify→confirm) via :meth:`link_finding`
(rule #1). Thread-safe, because a fleet of agents reads and writes concurrently.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any

from ..logging import get_logger

if TYPE_CHECKING:
    from ..ad.graph import ADAttackPath, ADGraph
from ..schemas.beliefs import Hypothesis, HypothesisStatus, Observation
from ..schemas.chains import AttackChain
from ..schemas.common import utcnow
from ..schemas.findings import Asset
from .store import KnowledgeStore

_log = get_logger("knowledge.worldmodel")


class WorldModel:
    """Per-engagement belief state: hypotheses plus queries the planner needs."""

    def __init__(self, engagement_id: str, store: KnowledgeStore | None = None) -> None:
        self.engagement_id = engagement_id
        self._store = store
        self._hypotheses: dict[str, Hypothesis] = {}
        self._chains: dict[str, AttackChain] = {}
        self._ad_graph: Any = None  # lazily-built ADGraph (identity attack graph)
        self._owned: set[str] = set()  # principals the fleet currently controls
        self._lock = threading.RLock()

    @property
    def store(self) -> KnowledgeStore | None:
        """The deterministic knowledge store this belief state complements."""

        return self._store

    def find_hypothesis(self, *, kind: str, subject: str) -> Hypothesis | None:
        """First hypothesis matching (kind, subject), or None — for dedup."""

        with self._lock:
            for h in self._hypotheses.values():
                if h.kind == kind and h.subject == subject:
                    return h
        return None

    # --- hypotheses -----------------------------------------------------------

    def add_hypothesis(
        self,
        *,
        subject: str,
        kind: str,
        title: str,
        rationale: str = "",
        prior: float = 0.3,
        suggested_tools: tuple[str, ...] = (),
        created_by: str = "ideator",
        observations: tuple[Observation, ...] = (),
    ) -> Hypothesis:
        """Register a new lead. Initial confidence is the prior, fused with any
        seed observations."""

        confidence = self._fuse(observations, prior)
        hypo = Hypothesis(
            engagement_id=self.engagement_id,
            subject=subject,
            kind=kind,
            title=title,
            rationale=rationale,
            prior=prior,
            confidence=confidence,
            observations=tuple(observations),
            suggested_tools=tuple(suggested_tools),
            created_by=created_by,
        )
        with self._lock:
            self._hypotheses[hypo.id] = hypo
        _log.debug("hypothesis added", id=hypo.id, kind=kind, confidence=confidence)
        return hypo

    def observe(self, hypothesis_id: str, observation: Observation) -> Hypothesis:
        """Fold a new signal into a hypothesis and re-fuse its confidence.

        A first observation moves an ``OPEN`` lead to ``TESTING``. Status is not
        auto-promoted to ``SUPPORTED``/``REFUTED`` here — that is a reasoning
        decision the caller (loop/Skeptic) makes via :meth:`set_status`.
        """

        with self._lock:
            current = self._hypotheses[hypothesis_id]
            observations = (*current.observations, observation)
            confidence = self._fuse(observations, current.prior)
            status = current.status
            if status is HypothesisStatus.OPEN:
                status = HypothesisStatus.TESTING
            updated = current.model_copy(
                update={
                    "observations": observations,
                    "confidence": confidence,
                    "status": status,
                    "updated_at": utcnow().isoformat(),
                }
            )
            self._hypotheses[hypothesis_id] = updated
            return updated

    def set_status(self, hypothesis_id: str, status: HypothesisStatus) -> Hypothesis:
        """Move a hypothesis to a new status (the loop/Skeptic's judgement)."""

        with self._lock:
            current = self._hypotheses[hypothesis_id]
            updated = current.model_copy(
                update={"status": status, "updated_at": utcnow().isoformat()}
            )
            self._hypotheses[hypothesis_id] = updated
            return updated

    def refute(self, hypothesis_id: str, reason: str, *, source: str = "skeptic") -> Hypothesis:
        """Record a refuting observation and mark the lead dead."""

        self.observe(
            hypothesis_id,
            Observation(source=source, probability=0.0, note=reason),
        )
        return self.set_status(hypothesis_id, HypothesisStatus.REFUTED)

    def link_finding(self, hypothesis_id: str, finding_id: str) -> Hypothesis:
        """Graduate a hypothesis: its truth now lives in a Finding (rule #1)."""

        with self._lock:
            current = self._hypotheses[hypothesis_id]
            updated = current.model_copy(
                update={"finding_id": finding_id, "updated_at": utcnow().isoformat()}
            )
            self._hypotheses[hypothesis_id] = updated
            return updated

    def get_hypothesis(self, hypothesis_id: str) -> Hypothesis | None:
        with self._lock:
            return self._hypotheses.get(hypothesis_id)

    def hypotheses(self, status: HypothesisStatus | None = None) -> list[Hypothesis]:
        with self._lock:
            values = list(self._hypotheses.values())
        if status is None:
            return values
        return [h for h in values if h.status is status]

    # --- attack chains --------------------------------------------------------

    def put_chain(self, chain: AttackChain) -> AttackChain:
        """Store or replace an attack chain (keyed by its id)."""

        with self._lock:
            self._chains[chain.id] = chain
        return chain

    def find_chain(self, *, entry_subject: str, objective: str) -> AttackChain | None:
        """First chain matching (entry_subject, objective), or None — for dedup."""

        with self._lock:
            for c in self._chains.values():
                if c.entry_subject == entry_subject and c.objective == objective:
                    return c
        return None

    def get_chain(self, chain_id: str) -> AttackChain | None:
        with self._lock:
            return self._chains.get(chain_id)

    def chains(self) -> list[AttackChain]:
        with self._lock:
            return list(self._chains.values())

    # --- identity / AD attack graph -------------------------------------------

    @property
    def ad_graph(self) -> ADGraph:
        """The identity attack graph (lazily created), shared across the fleet."""

        if self._ad_graph is None:
            from ..ad.graph import ADGraph
            self._ad_graph = ADGraph()
        return self._ad_graph  # type: ignore[no-any-return]

    def set_ad_graph(self, graph: ADGraph) -> None:
        """Replace the identity attack graph (e.g. after a fresh collection)."""

        with self._lock:
            self._ad_graph = graph

    def mark_owned(self, principal: str) -> None:
        """Record a principal the fleet now controls (a foothold identity)."""

        with self._lock:
            self._owned.add(principal.strip().upper())

    @property
    def owned_principals(self) -> list[str]:
        with self._lock:
            return sorted(self._owned)

    def domain_admin_paths(self) -> list[ADAttackPath]:
        """Known identity attack paths from an owned principal to a high-value
        target (Domain Admins / the domain object). Empty until one exists."""

        if self._ad_graph is None or not self._owned:
            return []
        return self.ad_graph.attack_paths(self.owned_principals)

    # --- planner query API ----------------------------------------------------

    def open_hypotheses(self, limit: int | None = None) -> list[Hypothesis]:
        """Live leads, highest-confidence first — what the planner picks from.

        "Live" = active (not refuted, not yet a Finding). Ordered by confidence
        desc, then oldest-first as a stable tie-break so ordering is
        deterministic (important for reproducible tests and audit).
        """

        with self._lock:
            active = [h for h in self._hypotheses.values() if h.is_active]
        active.sort(key=lambda h: (-h.confidence, h.created_at, h.id))
        return active if limit is None else active[:limit]

    def reachable_assets(self) -> list[Asset]:
        """In-scope assets reachable from the entry point (empty without a store).

        Reachability is a property of the attack graph, not the (default-``False``)
        ``Asset.reachable`` field the store leaves untouched at ingest — so we ask
        the graph, the same source the correlator uses.
        """

        if self._store is None:
            return []
        graph = self._store.graph
        return [a for a in self._store.assets() if graph.is_reachable(a.id)]

    def summary(self) -> dict[str, int]:
        """Compact counts for context assembly / narration."""

        with self._lock:
            by_status: dict[str, int] = {}
            for h in self._hypotheses.values():
                by_status[h.status.value] = by_status.get(h.status.value, 0) + 1
        out: dict[str, int] = {
            "hypotheses": len(self._hypotheses),
            "hypotheses_active": len(self.open_hypotheses()),
            "reachable_assets": len(self.reachable_assets()),
            "chains": len(self._chains),
            "chains_realised": sum(1 for c in self._chains.values() if c.is_realised),
        }
        out.update({f"hypotheses_{k}": v for k, v in by_status.items()})
        return out

    # --- internals ------------------------------------------------------------

    @staticmethod
    def _fuse(observations: tuple[Observation, ...], prior: float) -> float:
        """Bayesian log-odds fusion of observation confidences.

        Reuses the verify layer's fusion (imported lazily to avoid pulling the
        heavy ``verify`` package at ``knowledge`` import time). No observations →
        the prior is unchanged.
        """

        if not observations:
            return prior
        from ..verify.fusion import Evidence, fuse

        evidence = [
            Evidence(probability=o.probability, weight=o.weight, source=o.source)
            for o in observations
        ]
        return fuse(evidence, prior=prior)
