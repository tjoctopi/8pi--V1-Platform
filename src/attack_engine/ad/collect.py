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
          "domains":  [{"name": "CORP.LOCAL"}],
          "users":    [{"name": "...", "high_value": false}],
          "groups":   [{"name": "...", "members": ["..."]}],
          "computers":[{"name": "...", "local_admins": ["..."], "sessions": ["..."]}],
          "aces":     [{"principal": "...", "target": "...", "right": "GenericAll"}],
          # ACL/right names in `aces` also cover the domain-takeover primitives:
          #   DCSync · Owns · AddKeyCredentialLink · AllowedToDelegate ·
          #   AllowedToAct · ADCSESC1 · ADCSESC8 · SQLAdmin
          "kerberoastable": ["svc@corp"],   # has an SPN → request + crack its TGS
          "asrep_roastable": ["noauth@corp"] # no pre-auth → request + crack its AS-REP
        }

    Kerberoastable / AS-REP entries are recorded as *credential leads* (flags),
    not free graph edges — acquiring them requires cracking (the credential
    lifecycle), so they are surfaced for the planner rather than auto-traversed.
    """

    g = ADGraph()
    for dom in data.get("domains", []):
        g.add_principal(dom["name"], PrincipalKind.DOMAIN, high_value=True)
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
    for name in data.get("kerberoastable", []):
        g.mark_roastable(name)
    for name in data.get("asrep_roastable", []):
        g.mark_roastable(name, asrep=True)
    return g
