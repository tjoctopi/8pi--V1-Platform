"""Build an :class:`ADGraph` from collected AD data (BloodHound-style).

Accepts a normalized view of a domain — users, groups (with members), computers
(with local admins + active sessions), and ACL entries — and lays down the typed
attack edges. This is the adapter between a collector's output and the pathing
graph; the normalized shape keeps it collector-agnostic (SharpHound / BloodHound.py
adapters normalise into it).
"""

from __future__ import annotations

from typing import Any

from .graph import ADEdgeType, ADGraph, PrincipalKind


def from_bloodhound(data: dict[str, Any]) -> ADGraph:
    """Construct an AD attack graph from normalized collector data.

    Expected shape (all keys optional)::

        {
          "users":    [{"name": "...", "high_value": false}],
          "groups":   [{"name": "...", "members": ["..."]}],
          "computers":[{"name": "...", "local_admins": ["..."], "sessions": ["..."]}],
          "aces":     [{"principal": "...", "target": "...", "right": "GenericAll"}],
        }
    """

    g = ADGraph()
    for u in data.get("users", []):
        g.add_principal(u["name"], PrincipalKind.USER, high_value=bool(u.get("high_value")))
    for grp in data.get("groups", []):
        name = grp["name"]
        g.add_principal(name, PrincipalKind.GROUP, high_value=bool(grp.get("high_value")))
        for member in grp.get("members", []):
            g.add_edge(member, name, ADEdgeType.MEMBER_OF)
    for comp in data.get("computers", []):
        name = comp["name"]
        g.add_principal(name, PrincipalKind.COMPUTER)
        for admin in comp.get("local_admins", []):
            g.add_edge(admin, name, ADEdgeType.ADMIN_TO)
        for user in comp.get("sessions", []):
            g.add_edge(name, user, ADEdgeType.HAS_SESSION)
    for ace in data.get("aces", []):
        try:
            edge_type = ADEdgeType(ace["right"])
        except (ValueError, KeyError):
            continue  # unknown/unsupported right → skip (extensible)
        g.add_edge(ace["principal"], ace["target"], edge_type)
    return g
