"""Pydantic schemas — the contracts every component builds against (spec §6).

Importing from ``attack_engine.schemas`` gives you the whole vocabulary:
scope/RoE, findings/assets, blackboard events, tool contracts, and the
declarative agent spec.
"""

from __future__ import annotations

from .agentspec import (
    AgentSpec,
    Archetype,
    Guardrails,
    ModelTier,
    StopConditions,
)
from .common import StrictModel, iso_now, new_id, utcnow
from .events import Event, EventType
from .findings import Asset, Finding, FindingState, Priority, Service
from .remediation import (
    Remediation,
    RemediationKind,
    RemediationStatus,
    RetestResult,
)
from .scope import RateLimit, RulesOfEngagement, Scope
from .tools import ToolProfile, ToolResult

__all__ = [
    # common
    "StrictModel",
    "new_id",
    "utcnow",
    "iso_now",
    # scope
    "Scope",
    "RulesOfEngagement",
    "RateLimit",
    # findings
    "Finding",
    "FindingState",
    "Priority",
    "Asset",
    "Service",
    # events
    "Event",
    "EventType",
    # tools
    "ToolProfile",
    "ToolResult",
    # remediation / re-test
    "Remediation",
    "RemediationKind",
    "RemediationStatus",
    "RetestResult",
    # agent spec
    "AgentSpec",
    "Archetype",
    "ModelTier",
    "Guardrails",
    "StopConditions",
]
