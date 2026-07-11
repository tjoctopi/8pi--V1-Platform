"""Governance — RoE, human gates, and the immutable audit log (spec §1, §7).

Governance is a feature, not a checkbox. Every tool call, proposed action, and
model decision lands in an append-only, hash-chained audit log tied to a signed
engagement. Anything with real-world effect passes a human-in-the-loop gate.
"""

from __future__ import annotations

from .audit import AuditEntry, AuditLog
from .gates import Gate, GateDecision, GateRequest, HumanGate, rbac_responder
from .rbac import AccessControl, Permission, Principal, Role
from .roe import RoEEvaluator

__all__ = [
    "AuditEntry",
    "AuditLog",
    "Gate",
    "GateDecision",
    "GateRequest",
    "HumanGate",
    "rbac_responder",
    "RoEEvaluator",
    "AccessControl",
    "Principal",
    "Role",
    "Permission",
]
