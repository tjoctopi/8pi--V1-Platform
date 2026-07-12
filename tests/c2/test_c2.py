"""C2 / post-exploitation (O3) tests: session manager, listeners, governed post-ex."""

from __future__ import annotations

import pytest

from attack_engine.c2.backend import MockC2Backend
from attack_engine.c2.postex import PostExOperator
from attack_engine.c2.session import SessionKind, SessionManager, SessionStatus
from attack_engine.errors import ScopeViolationError, StopConditionReached
from attack_engine.governance.audit import AuditLog
from attack_engine.governance.authorization import KillSwitch
from attack_engine.governance.gates import HumanGate, approve_all, deny_all
from attack_engine.schemas import RulesOfEngagement, Scope


def _scope(*, tier: int = 1, authorized=frozenset({"post_exploitation"})) -> Scope:
    return Scope(
        engagement_id="engagement-c2", allowed_cidrs=("10.5.0.0/24",),
        roe=RulesOfEngagement(autonomy_tier=tier, authorized_techniques=authorized),
        authorized_by="lead@8pi.ai", signature="signed",
    )


# --- SessionManager -----------------------------------------------------------

def test_open_session_in_scope_is_registered_and_audited() -> None:
    audit = AuditLog()
    mgr = SessionManager(_scope(), audit)
    s = mgr.open_session("10.5.0.12", kind=SessionKind.SHELL, opened_by="distcc_exec")
    assert s.status is SessionStatus.ACTIVE and s.host == "10.5.0.12"
    assert mgr.get(s.id) is s or mgr.get(s.id).id == s.id
    assert "c2.session.opened" in [e.action for e in audit.entries()]


def test_open_session_out_of_scope_refused() -> None:
    mgr = SessionManager(_scope(), AuditLog())
    with pytest.raises(ScopeViolationError):
        mgr.open_session("8.8.8.8")   # not in 10.5.0.0/24


def test_listener_and_close() -> None:
    audit = AuditLog()
    mgr = SessionManager(_scope(), audit)
    lsnr = mgr.add_listener("10.5.0.99", 4444)
    assert mgr.default_listener().id == lsnr.id
    s = mgr.open_session("10.5.0.12", listener_id=lsnr.id)
    assert mgr.close_all() == 1
    assert mgr.get(s.id).status is SessionStatus.CLOSED
    actions = [e.action for e in audit.entries()]
    assert "c2.listener.add" in actions and "c2.session.closed" in actions


# --- PostExOperator: governance ----------------------------------------------

def _operator(scope, backend, *, responder=approve_all(), kill=None) -> PostExOperator:
    audit = AuditLog()
    return PostExOperator(
        SessionManager(scope, audit), backend, scope, audit,
        gate=HumanGate(audit, responder=responder), kill_switch=kill,
    ), audit


def test_enumerate_runs_autonomously_under_tier1() -> None:
    backend = MockC2Backend({"id": "uid=1(daemon)", "hostname": "metasploitable",
                             "default": "ok"})
    op, audit = _operator(_scope(tier=1), backend, responder=deny_all)  # deny would block if gated
    session = op._mgr.open_session("10.5.0.12", opened_by="test")
    report = op.enumerate(session)
    assert len(report.results) == len(backend.commands) >= 3
    assert any(r.command == "id" and "daemon" in r.output for r in report.results)
    actions = [e.action for e in audit.entries()]
    assert "action.authorized" in actions and "c2.postex" in actions
    assert "gate.request" not in actions  # no human consulted at Tier 1


def test_tier0_gates_postex() -> None:
    op, audit = _operator(_scope(tier=0), MockC2Backend(), responder=approve_all())
    session = op._mgr.open_session("10.5.0.12")
    op.enumerate(session)
    assert "gate.request" in [e.action for e in audit.entries()]  # human in the loop


def test_tier0_denied_runs_nothing() -> None:
    backend = MockC2Backend()
    op, _ = _operator(_scope(tier=0), backend, responder=deny_all)
    session = op._mgr.open_session("10.5.0.12")
    report = op.enumerate(session)
    assert report.gated_denied == 1 and report.results == []
    assert backend.commands == []  # no command reached the session


def test_kill_switch_halts_postex() -> None:
    ks = KillSwitch()
    ks.trip(reason="operator halt")
    op, _ = _operator(_scope(tier=1), MockC2Backend(), kill=ks)
    session = op._mgr.open_session("10.5.0.12")
    with pytest.raises(StopConditionReached):
        op.enumerate(session)


def test_pivot_recon_scope_checks_target() -> None:
    op, audit = _operator(_scope(tier=1), MockC2Backend({"default": "reachable"}))
    session = op._mgr.open_session("10.5.0.12")
    result = op.pivot_recon(session, "10.5.0.20")   # in scope
    assert result is not None and result.action == "pivot_recon"
    assert "c2.pivot" in [e.action for e in audit.entries()]
    with pytest.raises(ScopeViolationError):
        op.pivot_recon(session, "8.8.8.8")          # out of scope
