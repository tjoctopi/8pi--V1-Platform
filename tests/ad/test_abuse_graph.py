"""Phase-E abuse-graph depth — the domain-takeover primitives that actually own a
forest: DCSync, delegation/RBCD, shadow credentials, ADCS ESC1, and Kerberoast/
AS-REP credential leads. Each is proven to lay down a real, traversable edge (or
lead) from collected BloodHound-shape data.
"""

from __future__ import annotations

from attack_engine.ad import from_bloodhound
from attack_engine.ad.graph import ADEdgeType, ADGraph, PrincipalKind


def test_dcsync_on_domain_is_takeover() -> None:
    g = ADGraph()
    g.add_principal("CORP.LOCAL", PrincipalKind.DOMAIN)  # crown jewel (auto high-value)
    g.add_edge("svc@corp", "alice@corp", ADEdgeType.OWNS)  # noise
    g.add_edge("alice@corp", "svc@corp", ADEdgeType.FORCE_CHANGE_PASSWORD)
    g.add_edge("svc@corp", "CORP.LOCAL", ADEdgeType.DCSYNC)
    [p] = g.attack_paths(["alice@corp"])
    assert p.target == "CORP.LOCAL"
    assert p.techniques == ["T1098", "T1003.006"]  # ForceChangePassword → DCSync


def test_adcs_esc1_reaches_domain_admins() -> None:
    g = ADGraph()
    g.add_principal("Domain Admins@corp", PrincipalKind.GROUP)
    g.add_edge("low@corp", "Domain Admins@corp", ADEdgeType.ADCS_ESC1)
    [p] = g.attack_paths(["low@corp"])
    assert p.edges[0].edge_type is ADEdgeType.ADCS_ESC1 and p.edges[0].technique == "T1649"


def test_rbcd_and_shadow_credentials_traverse() -> None:
    for right, tid in (("AllowedToAct", "T1558"), ("AddKeyCredentialLink", "T1556")):
        g = from_bloodhound({
            "domains": [{"name": "CORP.LOCAL"}],
            "aces": [
                {"principal": "attacker@corp", "target": "DC01@corp", "right": right},
                {"principal": "DC01@corp", "target": "CORP.LOCAL", "right": "DCSync"},
            ],
        })
        [p] = g.attack_paths(["attacker@corp"])
        assert p.target == "CORP.LOCAL"
        assert p.edges[0].technique == tid


def test_kerberoast_and_asrep_surface_as_credential_leads() -> None:
    g = from_bloodhound({
        "users": [{"name": "svc_sql@corp"}, {"name": "noauth@corp"}],
        "kerberoastable": ["svc_sql@corp"],
        "asrep_roastable": ["noauth@corp"],
    })
    leads = {r["principal"]: r["technique"] for r in g.roastable()}
    assert leads["SVC_SQL@CORP"] == "kerberoast"
    assert leads["NOAUTH@CORP"] == "asrep"


def test_realistic_foothold_to_domain_admin_via_new_primitives() -> None:
    # Owned low-priv user → group with GenericWrite over a delegation-capable box
    # → RBCD → DCSync on the domain. A full, realistic identity kill chain.
    data = {
        "domains": [{"name": "CORP.LOCAL"}],
        "users": [{"name": "alice@corp"}, {"name": "dc01$@corp"}],
        "groups": [{"name": "HelpDesk@corp", "members": ["alice@corp"]}],
        "computers": [{"name": "DC01@corp"}],
        "aces": [
            {"principal": "HelpDesk@corp", "target": "dc01$@corp", "right": "AllowedToAct"},
            {"principal": "dc01$@corp", "target": "CORP.LOCAL", "right": "DCSync"},
        ],
    }
    g = from_bloodhound(data)
    [p] = g.attack_paths(["alice@corp"])
    assert p.target == "CORP.LOCAL"
    assert p.techniques == ["T1069", "T1558", "T1003.006"]  # MemberOf → RBCD → DCSync


def test_unknown_high_value_still_needs_a_path() -> None:
    g = from_bloodhound({"domains": [{"name": "CORP.LOCAL"}],
                         "users": [{"name": "lonely@corp"}]})
    assert g.attack_paths(["lonely@corp"]) == []  # no edge to the domain → no path
