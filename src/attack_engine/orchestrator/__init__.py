"""Control plane — the Orchestrator and the full coordinated loop (spec §3)."""

from __future__ import annotations

from .adversary import (
    AdversaryCampaign,
    CampaignOutcome,
    CampaignPhase,
    PhaseRun,
    seed_targets,
)
from .controller import ControllerResult, ObjectiveController
from .objective import (
    ConfidenceObjective,
    DomainAdminObjective,
    MapSurfaceObjective,
    Objective,
)
from .orchestrator import LoopResult, Orchestrator
from .plan import AttackPlan, Phase, build_plan, prioritize_targets
from .report import EngagementReport, build_report
from .retest import RetestRunner

__all__ = [
    "Orchestrator",
    "LoopResult",
    "AttackPlan",
    "Phase",
    "build_plan",
    "prioritize_targets",
    "RetestRunner",
    "EngagementReport",
    "build_report",
    "ObjectiveController",
    "ControllerResult",
    "Objective",
    "MapSurfaceObjective",
    "ConfidenceObjective",
    "DomainAdminObjective",
    "AdversaryCampaign",
    "CampaignOutcome",
    "CampaignPhase",
    "PhaseRun",
    "seed_targets",
]
