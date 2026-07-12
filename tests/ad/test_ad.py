"""AD attack-path graph + identity attack tools (O5) tests."""

from __future__ import annotations

import pytest

from attack_engine.ad import from_bloodhound
from attack_engine.ad.graph import ADEdgeType, ADGraph, PrincipalKind
from attack_engine.schemas.tools import ToolProfile
from attack_engine.toolrunner.sandbox import SandboxResult
from attack_engine.toolrunner.wrappers.bloodhound import BloodHoundWrapper
from attack_engine.toolrunner.wrappers.kerberoast import KerberoastWrapper

# --- ADGraph pathing ----------------------------------------------------------

def test_shortest_path_to_domain_admin() -> None:
    g = ADGraph()
    g.add_principal("alice@corp", PrincipalKind.USER)
    g.add_principal("Domain Admins@corp", PrincipalKind.GROUP)  # auto high-value
    g.add_principal("IT@corp", PrincipalKind.GROUP)
    g.add_principal("WS01@corp", PrincipalKind.COMPUTER)
    g.add_edge("alice@corp", "IT@corp", ADEdgeType.MEMBER_OF)
    g.add_edge("IT@corp", "WS01@corp", ADEdgeType.ADMIN_TO)
    g.add_edge("WS01@corp", "dave@corp", ADEdgeType.HAS_SESSION)
    g.add_edge("dave@corp", "Domain Admins@corp", ADEdgeType.MEMBER_OF)

    paths = g.attack_paths(["alice@corp"])
    assert len(paths) == 1
    p = paths[0]
    assert p.target == "DOMAIN ADMINS@CORP"
    assert p.techniques == ["T1069", "T1021.002", "T1003", "T1069"]
    assert p.cost == 2.0  # MemberOf(0)+AdminTo(1)+HasSession(1)+MemberOf(0)


def test_no_path_returns_empty() -> None:
    g = ADGraph()
    g.add_principal("bob@corp", PrincipalKind.USER)
    g.add_principal("Domain Admins@corp", PrincipalKind.GROUP)
    assert g.attack_paths(["bob@corp"]) == []


def test_cheapest_path_preferred() -> None:
    g = ADGraph()
    g.add_principal("Domain Admins@corp", PrincipalKind.GROUP)
    # Direct ACL takeover (cost 1) vs a longer route.
    g.add_edge("eve@corp", "Domain Admins@corp", ADEdgeType.GENERIC_ALL)      # cost 1
    g.add_edge("eve@corp", "mid@corp", ADEdgeType.WRITE_DACL)                 # cost 2
    g.add_edge("mid@corp", "Domain Admins@corp", ADEdgeType.ADD_MEMBER)       # +1
    p = g.attack_paths(["eve@corp"])[0]
    assert p.cost == 1.0 and p.edges[0].edge_type is ADEdgeType.GENERIC_ALL


def test_from_bloodhound_builds_paths() -> None:
    data = {
        "users": [{"name": "alice@corp"}, {"name": "admin@corp"}],
        "groups": [
            {"name": "Domain Admins@corp", "members": ["admin@corp"]},
            {"name": "IT@corp", "members": ["alice@corp"]},
        ],
        "computers": [{"name": "WS01@corp", "local_admins": ["IT@corp"],
                       "sessions": ["admin@corp"]}],
        "aces": [{"principal": "alice@corp", "target": "svc@corp",
                  "right": "ForceChangePassword"}],
    }
    g = from_bloodhound(data)
    assert g.principal_count >= 5
    paths = g.attack_paths(["alice@corp"])
    assert paths and paths[0].target == "DOMAIN ADMINS@CORP"


def test_from_bloodhound_skips_unknown_ace_right() -> None:
    g = from_bloodhound({"aces": [{"principal": "a@c", "target": "b@c", "right": "Bogus"}]})
    assert g.edge_count == 0  # unknown right ignored


# --- tool wrappers ------------------------------------------------------------

def test_bloodhound_argv_and_requires_creds() -> None:
    argv = BloodHoundWrapper().build_argv("10.5.0.5", ToolProfile(args={
        "domain": "corp.local", "username": "svc", "password": "pw"}))
    assert argv[0] == "bloodhound-python"
    assert "-d" in argv and "corp.local" in argv and "-ns" in argv and "10.5.0.5" in argv
    assert "-p" in argv
    assert BloodHoundWrapper().is_mutating(ToolProfile()) is False
    with pytest.raises(ValueError, match="domain"):
        BloodHoundWrapper().build_argv("10.5.0.5", ToolProfile())


def test_kerberoast_argv_and_parse() -> None:
    w = KerberoastWrapper()
    argv = w.build_argv("10.5.0.5", ToolProfile(args={
        "domain": "corp.local", "username": "svc", "password": "pw"}))
    assert argv[0] == "GetUserSPNs.py" and "-request" in argv
    out = SandboxResult(
        0, b"$krb5tgs$23$*svc$CORP$...*$abcdef0123\nServicePrincipalName ...\n", b"", 0.1, "f")
    parsed = w.parse("10.5.0.5", out)
    assert parsed["roastable"] is True and parsed["hash_count"] == 1 and parsed["kind"] == "tgs"


def test_kerberoast_asrep_mode() -> None:
    argv = KerberoastWrapper().build_argv("10.5.0.5", ToolProfile(args={
        "domain": "corp.local", "username": "svc", "mode": "asrep"}))
    assert argv[0] == "GetNPUsers.py"


# --- ATT&CK catalog additions -------------------------------------------------

def test_catalog_has_ad_techniques_available() -> None:
    from attack_engine.attack import build_library

    lib = build_library()
    for tid in ("T1087", "T1069", "T1558.003", "T1558.004"):
        t = lib.get(tid)
        assert t is not None and t.available, f"{tid} should be available"
