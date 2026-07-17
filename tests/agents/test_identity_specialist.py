"""Identity/AD specialist — world-model AD-graph integration, the ADObserver
(collection + roast leads → beliefs), the Domain-Admin objective, and the loop.
"""

from __future__ import annotations

import pytest

from attack_engine.agents.actions import ActionOutcome, ProposedAction
from attack_engine.agents.context import AgentContext
from attack_engine.agents.identity_specialist import ADObserver, build_identity_loop
from attack_engine.agents.reasoning import LoopContext
from attack_engine.knowledge.worldmodel import WorldModel
from attack_engine.orchestrator.objective import DomainAdminObjective
from attack_engine.schemas.tools import ToolResult

# A realistic collection: alice (owned) → HelpDesk → RBCD on DC → DCSync → domain.
_COLLECTION = {
    "domains": [{"name": "CORP.LOCAL"}],
    "users": [{"name": "alice@corp"}, {"name": "dc01$@corp"}],
    "groups": [{"name": "HelpDesk@corp", "members": ["alice@corp"]}],
    "computers": [{"name": "DC01@corp"}],
    "aces": [
        {"principal": "HelpDesk@corp", "target": "dc01$@corp", "right": "AllowedToAct"},
        {"principal": "dc01$@corp", "target": "CORP.LOCAL", "right": "DCSync"},
    ],
    "kerberoastable": ["svc_sql@corp"],
}


def _loop_ctx(wm: WorldModel) -> LoopContext:
    return LoopContext(wm, objective="da", history=(), step=0, budget=None)


def _tool_result(tool: str, target: str, parsed: dict) -> ToolResult:
    return ToolResult(tool=tool, target=target, raw=b"", parsed=parsed, exit_code=0,
                      audit_id="aud", engagement_id="eng-1")


# --- world-model AD integration -------------------------------------------------


def test_world_model_tracks_owned_and_paths() -> None:
    wm = WorldModel("eng-1")
    assert wm.domain_admin_paths() == []  # no graph / no owned yet
    from attack_engine.ad.collect import from_bloodhound
    wm.set_ad_graph(from_bloodhound(_COLLECTION))
    assert wm.domain_admin_paths() == []  # graph but nothing owned
    wm.mark_owned("alice@corp")
    paths = wm.domain_admin_paths()
    assert paths and paths[0].target == "CORP.LOCAL"


# --- ADObserver -----------------------------------------------------------------


def test_ingest_collection_surfaces_path_belief() -> None:
    wm = WorldModel("eng-1")
    ADObserver.ingest_collection(wm, _COLLECTION, owned=["alice@corp"])
    paths = [h for h in wm.open_hypotheses() if h.kind == "ad-path"]
    assert len(paths) == 1
    assert "CORP.LOCAL" in paths[0].subject
    assert "DCSync" in paths[0].rationale


def test_observer_kerberoast_marks_roastable_and_lead() -> None:
    wm = WorldModel("eng-1")
    ADObserver().observe(
        ProposedAction(tool="kerberoast", target="10.5.0.5",
                       rationale="roast", params={"account": "svc_sql@corp"}),
        ActionOutcome(ok=True, summary="ok",
                      raw=_tool_result("kerberoast", "10.5.0.5",
                                       {"roastable": True, "kind": "tgs", "hash_count": 1})),
        _loop_ctx(wm),
    )
    lead = [h for h in wm.open_hypotheses() if h.kind == "ad-credential"]
    assert lead and "Kerberoast" in lead[0].title
    assert {r["principal"] for r in wm.ad_graph.roastable()} == {"SVC_SQL@CORP"}


_TGS_SVC_SQL = (
    "$krb5tgs$23$*svc_sql*CORP.LOCAL*MSSQL/db*$"
    "5bf73a77ffb2392433271d4b7c2fc8d1$"
    "364a207fe91c05e8eaeaf5d775c6bdf726f9edd61276cd52b62d8fcdcab9"
)


def test_observer_cracks_and_owns_roasted_principal_surfacing_da_path() -> None:
    """E3 end-to-end: a Kerberoast result → capture → crack → own → new DA path."""

    from attack_engine.ad.graph import ADEdgeType, ADGraph, PrincipalKind
    from attack_engine.credentials.manager import CredentialManager
    from attack_engine.governance.audit import AuditLog

    # svc_sql holds GenericAll over Domain Admins — but nothing is owned yet.
    graph = ADGraph()
    graph.add_principal("svc_sql@CORP.LOCAL", PrincipalKind.USER)
    graph.add_principal("Domain Admins", PrincipalKind.GROUP, high_value=True)
    graph.add_edge("SVC_SQL@CORP.LOCAL", "DOMAIN ADMINS", ADEdgeType.GENERIC_ALL)
    wm = WorldModel("eng-1")
    wm.set_ad_graph(graph)
    assert wm.domain_admin_paths() == []

    mgr = CredentialManager("eng-1", AuditLog())
    observer = ADObserver(cred_manager=mgr, wordlist=["Winter2025", "Summer2026!"])
    observer.observe(
        ProposedAction(tool="kerberoast", target="10.5.0.20", rationale="roast",
                       params={"account": "svc_sql@CORP.LOCAL"}),
        ActionOutcome(ok=True, summary="ok",
                      raw=_tool_result("kerberoast", "10.5.0.20",
                                       {"roastable": True, "kind": "tgs", "hash_count": 1,
                                        "hashes": [_TGS_SVC_SQL],
                                        "accounts": ["svc_sql@CORP.LOCAL"]})),
        _loop_ctx(wm),
    )
    # Owned the cracked account → the path to Domain Admins now exists and is surfaced.
    assert "SVC_SQL@CORP.LOCAL" in wm.owned_principals
    paths = wm.domain_admin_paths()
    assert paths and paths[0].target == "DOMAIN ADMINS"
    assert any(h.kind == "ad-path" for h in wm.open_hypotheses())


def test_observer_without_manager_only_records_lead() -> None:
    """No credential manager configured → the observer records the lead, no crack."""

    wm = WorldModel("eng-1")
    ADObserver().observe(
        ProposedAction(tool="kerberoast", target="10.5.0.20", rationale="roast",
                       params={"account": "svc_sql@CORP.LOCAL"}),
        ActionOutcome(ok=True, summary="ok",
                      raw=_tool_result("kerberoast", "10.5.0.20",
                                       {"roastable": True, "kind": "tgs", "hash_count": 1,
                                        "hashes": [_TGS_SVC_SQL]})),
        _loop_ctx(wm),
    )
    assert wm.owned_principals == []
    assert any(h.kind == "ad-credential" for h in wm.open_hypotheses())


def test_observer_bloodhound_with_data_builds_graph() -> None:
    wm = WorldModel("eng-1")
    wm.mark_owned("alice@corp")
    ADObserver().observe(
        ProposedAction(tool="bloodhound", target="10.5.0.5", rationale="collect"),
        ActionOutcome(ok=True, summary="ok",
                      raw=_tool_result("bloodhound", "10.5.0.5", {"data": _COLLECTION})),
        _loop_ctx(wm),
    )
    assert any(h.kind == "ad-path" for h in wm.open_hypotheses())


def test_observer_ignores_failed_outcome() -> None:
    wm = WorldModel("eng-1")
    ADObserver().observe(
        ProposedAction(tool="bloodhound", target="t", rationale="x"),
        ActionOutcome(ok=False, summary="degraded", raw=None), _loop_ctx(wm),
    )
    assert wm.hypotheses() == []


# --- Domain-Admin objective -----------------------------------------------------


def test_domain_admin_objective_fires_only_with_a_path() -> None:
    wm = WorldModel("eng-1")
    obj = DomainAdminObjective()
    assert obj.is_satisfied(wm) is False
    ADObserver.ingest_collection(wm, _COLLECTION, owned=["alice@corp"])
    assert obj.is_satisfied(wm) is True


def test_objective_not_satisfied_without_owned_principal() -> None:
    wm = WorldModel("eng-1")
    ADObserver.ingest_collection(wm, _COLLECTION)  # graph built, nothing owned
    assert DomainAdminObjective().is_satisfied(wm) is False


# --- factory --------------------------------------------------------------------


def test_build_identity_loop_requires_gateway(ctx: AgentContext) -> None:
    ctx.gateway = None
    with pytest.raises(ValueError, match="model gateway"):
        build_identity_loop(ctx)
