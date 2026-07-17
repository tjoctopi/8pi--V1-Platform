"""Active Directory attack-path graph — BloodHound-style pathing to Domain Admin.

Principals (users/groups/computers) are nodes; the attack primitives between them
(``MemberOf``, ``AdminTo``, ``HasSession``, ACL abuses, remote access) are typed,
weighted directed edges — each carrying the ATT&CK technique an attacker would
use to traverse it. :meth:`ADGraph.attack_paths` returns the cheapest path from an
owned principal to a high-value target (Domain Admins by default), edge by edge —
the identity attack path an operator (or the autonomous planner) executes.
"""

from __future__ import annotations

from enum import Enum
from itertools import pairwise

import networkx as nx

from ..schemas.common import StrictModel


class PrincipalKind(str, Enum):
    USER = "user"
    GROUP = "group"
    COMPUTER = "computer"
    DOMAIN = "domain"


class ADEdgeType(str, Enum):
    """BloodHound-style edges an attacker traverses (value = edge label)."""

    MEMBER_OF = "MemberOf"
    ADMIN_TO = "AdminTo"
    HAS_SESSION = "HasSession"
    GENERIC_ALL = "GenericAll"
    GENERIC_WRITE = "GenericWrite"
    WRITE_DACL = "WriteDacl"
    WRITE_OWNER = "WriteOwner"
    FORCE_CHANGE_PASSWORD = "ForceChangePassword"
    ADD_MEMBER = "AddMember"
    CAN_RDP = "CanRDP"
    CAN_PSREMOTE = "CanPSRemote"
    # --- domain-takeover primitives (Phase E depth) ---
    OWNS = "Owns"                                    # object ownership → grant self rights
    DCSYNC = "DCSync"                                # replicate secrets → all hashes
    ADD_KEY_CREDENTIAL_LINK = "AddKeyCredentialLink"  # shadow credentials
    ALLOWED_TO_DELEGATE = "AllowedToDelegate"        # constrained delegation (S4U2Proxy)
    ALLOWED_TO_ACT = "AllowedToAct"                  # resource-based constrained delegation
    ADCS_ESC1 = "ADCSESC1"                           # enroll a cert as any principal
    ADCS_ESC8 = "ADCSESC8"                           # NTLM relay to AD CS web enrollment
    SQL_ADMIN = "SQLAdmin"                           # MSSQL admin → xp_cmdshell


#: Per-edge ATT&CK technique + traversal cost. MemberOf is free (already implied
#: by group membership); everything else is a real attacker action with a cost,
#: so the cheapest path favours fewer/easier hops (BloodHound's shortest-path).
_EDGE_META: dict[ADEdgeType, tuple[str, float]] = {
    ADEdgeType.MEMBER_OF: ("T1069", 0.0),            # Permission Groups Discovery
    ADEdgeType.ADMIN_TO: ("T1021.002", 1.0),         # SMB/Admin Shares
    ADEdgeType.HAS_SESSION: ("T1003", 1.0),          # OS Credential Dumping
    ADEdgeType.GENERIC_ALL: ("T1098", 1.0),          # Account Manipulation
    ADEdgeType.GENERIC_WRITE: ("T1098", 1.5),
    ADEdgeType.WRITE_DACL: ("T1222", 2.0),           # Permissions Modification
    ADEdgeType.WRITE_OWNER: ("T1222", 2.0),
    ADEdgeType.FORCE_CHANGE_PASSWORD: ("T1098", 1.0),
    ADEdgeType.ADD_MEMBER: ("T1098", 1.0),
    ADEdgeType.CAN_RDP: ("T1021.001", 1.0),          # Remote Desktop
    ADEdgeType.CAN_PSREMOTE: ("T1021.006", 1.0),     # PowerShell Remoting
    ADEdgeType.OWNS: ("T1098", 1.0),
    ADEdgeType.DCSYNC: ("T1003.006", 1.0),           # DCSync (replicate secrets)
    ADEdgeType.ADD_KEY_CREDENTIAL_LINK: ("T1556", 1.0),  # Shadow Credentials
    ADEdgeType.ALLOWED_TO_DELEGATE: ("T1558.003", 1.5),  # Kerberoasting/constrained deleg.
    ADEdgeType.ALLOWED_TO_ACT: ("T1558", 1.5),       # RBCD
    ADEdgeType.ADCS_ESC1: ("T1649", 1.0),            # Steal/Forge Certificates
    ADEdgeType.ADCS_ESC8: ("T1649", 1.5),
    ADEdgeType.SQL_ADMIN: ("T1210", 1.0),
}

#: High-value groups whose membership means domain takeover.
_HIGH_VALUE_GROUPS = ("domain admins", "enterprise admins", "administrators",
                      "domain controllers")


class ADEdge(StrictModel):
    src: str
    dst: str
    edge_type: ADEdgeType
    technique: str
    cost: float


class ADAttackPath(StrictModel):
    """An ordered identity attack path from an owned principal to a target."""

    start: str
    target: str
    edges: list[ADEdge]
    cost: float

    @property
    def techniques(self) -> list[str]:
        return [e.technique for e in self.edges]

    def to_markdown(self) -> str:
        line = f"**{self.start}** → **{self.target}** (cost {self.cost:.1f})"
        steps = [
            f"  {i}. {e.src} —[{e.edge_type.value} / {e.technique}]→ {e.dst}"
            for i, e in enumerate(self.edges, 1)
        ]
        return "\n".join([line, *steps])


class ADGraph:
    """A directed AD attack graph with shortest-path-to-Domain-Admin pathing."""

    def __init__(self) -> None:
        self._g = nx.DiGraph()

    def add_principal(self, name: str, kind: PrincipalKind, *, high_value: bool = False) -> str:
        key = name.strip().upper()
        # A DOMAIN object is a crown jewel: controlling it (DCSync / GenericAll on
        # the domain) is domain takeover, so it is high-value by definition.
        hv = (high_value or kind is PrincipalKind.DOMAIN
              or any(g in name.lower() for g in _HIGH_VALUE_GROUPS))
        if self._g.has_node(key):
            if hv:
                self._g.nodes[key]["high_value"] = True
        else:
            self._g.add_node(key, kind=kind.value, high_value=hv)
        return key

    def add_edge(self, src: str, dst: str, edge_type: ADEdgeType) -> None:
        s, d = src.strip().upper(), dst.strip().upper()
        # Endpoints must exist; default unknown endpoints to users (safe).
        for node in (s, d):
            if not self._g.has_node(node):
                self.add_principal(node, PrincipalKind.USER)
        technique, cost = _EDGE_META[edge_type]
        self._g.add_edge(s, d, edge_type=edge_type, technique=technique, cost=cost)

    def high_value_targets(self) -> list[str]:
        return [n for n, a in self._g.nodes(data=True) if a.get("high_value")]

    def mark_roastable(self, name: str, *, asrep: bool = False) -> str:
        """Flag a principal as Kerberoastable / AS-REP-roastable — a credential
        lead: an authenticated attacker can request its ticket and crack it
        offline to *become* it (the crack itself is the credential lifecycle)."""

        key = self.add_principal(name, PrincipalKind.USER)
        self._g.nodes[key]["asrep_roastable" if asrep else "kerberoastable"] = True
        return key

    def roastable(self) -> list[dict[str, str]]:
        """Roastable principals and which technique acquires their credential."""

        out: list[dict[str, str]] = []
        for n, a in self._g.nodes(data=True):
            if a.get("kerberoastable"):
                out.append({"principal": n, "technique": "kerberoast", "attack": "T1558.003"})
            if a.get("asrep_roastable"):
                out.append({"principal": n, "technique": "asrep", "attack": "T1558.004"})
        return out

    def attack_paths(
        self, owned: list[str], targets: list[str] | None = None
    ) -> list[ADAttackPath]:
        """Cheapest attack path from each owned principal to a high-value target.

        Returns one path per owned principal (its shortest route to any target),
        ranked cheapest-first. Empty if no path exists.
        """

        goals = [t.strip().upper() for t in (targets or self.high_value_targets())]
        goals = [g for g in goals if self._g.has_node(g)]
        paths: list[ADAttackPath] = []
        for principal in owned:
            start = principal.strip().upper()
            if not self._g.has_node(start):
                continue
            best: ADAttackPath | None = None
            for goal in goals:
                if start == goal:
                    continue
                try:
                    node_path = nx.shortest_path(self._g, start, goal, weight="cost")
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue
                edges = self._edges_of(node_path)
                total = sum(e.cost for e in edges)
                if best is None or total < best.cost:
                    best = ADAttackPath(start=start, target=goal, edges=edges, cost=total)
            if best is not None:
                paths.append(best)
        paths.sort(key=lambda p: p.cost)
        return paths

    def _edges_of(self, node_path: list[str]) -> list[ADEdge]:
        edges: list[ADEdge] = []
        for src, dst in pairwise(node_path):
            data = self._g.edges[src, dst]
            edges.append(ADEdge(src=src, dst=dst, edge_type=data["edge_type"],
                                technique=data["technique"], cost=data["cost"]))
        return edges

    @property
    def principal_count(self) -> int:
        return int(self._g.number_of_nodes())

    @property
    def edge_count(self) -> int:
        return int(self._g.number_of_edges())
