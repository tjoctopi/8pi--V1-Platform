"""Active Directory attack paths + identity attacks (O5).

Most enterprise compromise runs through identity. This package models an AD
domain as a directed graph of principals (users/groups/computers) and the
attack primitives between them (group membership, local-admin, sessions, ACL
abuses), and finds the shortest attack path from an owned principal to Domain
Admin — the BloodHound-style pathing that turns a foothold into domain takeover.

Collection (BloodHound) and credential attacks (Kerberoasting / AS-REP roasting)
are wrapped as scope-enforced, audited tools; the graph is the reasoning layer.
"""

from __future__ import annotations

from .collect import from_bloodhound
from .graph import ADAttackPath, ADEdge, ADEdgeType, ADGraph, PrincipalKind

__all__ = [
    "ADGraph",
    "ADEdge",
    "ADEdgeType",
    "ADAttackPath",
    "PrincipalKind",
    "from_bloodhound",
]
