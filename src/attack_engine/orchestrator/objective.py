"""Objectives — the named goal a campaign drives toward (spec §2, §3).

The old orchestrator ran a fixed 8-phase sequence regardless of intent. An
:class:`Objective` replaces that with a *goal*: a plain-language description the
Planner reasons about, plus a deterministic ``is_satisfied`` predicate over the
world model that says when we are done. Satisfaction is checked by code, not
judged by the model (rule #1) — the LLM decides *how* to pursue a goal; whether
it is *met* is a deterministic test.

Only objectives that are meaningful with today's capabilities live here. Surface
mapping and belief confidence were the first; :class:`DomainAdminObjective`
arrives with Phase E now that the world model carries an identity attack graph
and an owned-principal set — so its predicate genuinely fires.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..knowledge.worldmodel import WorldModel


class Objective(ABC):
    """A goal the controller pursues: a description plus a done-test."""

    @abstractmethod
    def describe(self) -> str:
        """Plain-language goal for the Planner's prompt."""

    @abstractmethod
    def is_satisfied(self, world_model: WorldModel) -> bool:
        """Deterministic check of whether the goal has been reached."""


class MapSurfaceObjective(Objective):
    """Map the attack surface: reach a target count of assets and/or leads."""

    def __init__(self, *, min_assets: int = 1, min_hypotheses: int = 0) -> None:
        self.min_assets = min_assets
        self.min_hypotheses = min_hypotheses

    def describe(self) -> str:
        return (
            f"Map the attack surface: discover at least {self.min_assets} reachable "
            f"asset(s) and surface at least {self.min_hypotheses} promising lead(s)."
        )

    def is_satisfied(self, world_model: WorldModel) -> bool:
        enough_assets = len(world_model.reachable_assets()) >= self.min_assets
        enough_leads = len(world_model.open_hypotheses()) >= self.min_hypotheses
        return enough_assets and enough_leads


class ConfidenceObjective(Objective):
    """Raise confidence in a specific lead to a threshold.

    Satisfied when any live hypothesis matching ``kind`` (and ``subject`` if
    given) reaches ``threshold``. Models "keep probing until you believe X".
    """

    def __init__(
        self, *, kind: str, threshold: float = 0.8, subject: str | None = None
    ) -> None:
        self.kind = kind
        self.threshold = threshold
        self.subject = subject

    def describe(self) -> str:
        where = f" on {self.subject}" if self.subject else ""
        return (
            f"Investigate the {self.kind} lead{where} until confidence reaches "
            f"{self.threshold:.0%} or it is refuted."
        )

    def is_satisfied(self, world_model: WorldModel) -> bool:
        for h in world_model.open_hypotheses():
            if h.kind != self.kind:
                continue
            if self.subject is not None and h.subject != self.subject:
                continue
            if h.confidence >= self.threshold:
                return True
        return False


class DomainAdminObjective(Objective):
    """Reach Domain Admin: an identity attack path from an owned principal to a
    high-value target (Domain Admins / the domain object).

    Satisfied deterministically the moment the world model's identity graph
    contains such a path from the current owned-principal set — the same
    shortest-path pathing BloodHound/the planner use. Confirmation that a hop
    *worked* is still a Finding/oracle's word (rule #1); this only asks whether a
    route is *known*.
    """

    def describe(self) -> str:
        return (
            "Reach Domain Admin: collect the identity graph, own a starting "
            "principal, and find an attack path to a Domain Admins / domain-object "
            "target — Kerberoast, DCSync, delegation/RBCD, ADCS or ACL abuse."
        )

    def is_satisfied(self, world_model: WorldModel) -> bool:
        return bool(world_model.domain_admin_paths())
