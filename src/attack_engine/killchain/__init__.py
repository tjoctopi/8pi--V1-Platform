"""Kill-chain planning — the goal-directed attacker's brain (planning only).

Builds a privilege-aware attack graph from confirmed footholds and computes the
cheapest route to an objective, phase-labelled and ATT&CK-mapped. Every impact
phase is flagged gated. This package *plans and reasons*; execution of impact
phases is human-gated and operator-driven — the engine never autonomously
escalates, moves laterally, or exfiltrates.
"""

from __future__ import annotations

from .graph import ExploitEdge, Position, PrivilegeGraph
from .plan import (
    GATED_PHASES,
    KillChainPhase,
    KillChainPlan,
    KillChainPlanner,
    KillChainStep,
    build_privilege_graph,
)

__all__ = [
    "PrivilegeGraph",
    "Position",
    "ExploitEdge",
    "KillChainPlanner",
    "KillChainPlan",
    "KillChainStep",
    "KillChainPhase",
    "GATED_PHASES",
    "build_privilege_graph",
]
