"""Foothold lifecycle (O2→O3): governed session open + proof-of-impact + teardown."""

from __future__ import annotations

import pytest

from attack_engine.c2.backend import MockC2Backend
from attack_engine.c2.foothold import FootholdRunner
from attack_engine.c2.session import SessionKind, SessionManager, SessionStatus
from attack_engine.errors import ScopeViolationError, StopConditionReached
from attack_engine.governance.audit import AuditLog
from attack_engine.governance.authorization import KillSwitch
from attack_engine.governance.gates import HumanGate, approve_all, deny_all
from attack_engine.schemas import RulesOfEngagement, Scope

_PROOF = {"id": "uid=0(root)", "whoami": "root", "hostname": "metasploitable", "default": "ok"}


def _scope(*, tier: int = 1, authorized=frozenset({"establish_foothold"})) -> Scope:
    return Scope(
        engagement_id="engagement-c2", allowed_cidrs=("10.5.0.0/24",),
        roe=RulesOfEngagement(autonomy_tier=tier, authorized_techniques=authorized),
        authorized_by="lead@8pi.ai", signature="signed",
    )


def _runner(scope, backend, *, responder=approve_all(), kill=None):
    audit = AuditLog()
    mgr = SessionManager(scope, audit)
    runner = FootholdRunner(
        mgr, backend, scope, audit,
        gate=HumanGate(audit, responder=responder), kill_switch=kill,
    )
    return runner, mgr, audit


# --- establish ------------------------------------------------------------------


def test_foothold_established_autonomously_at_tier1() -> None:
    backend = MockC2Backend(_PROOF)
    runner, mgr, audit = _runner(_scope(tier=1), backend, responder=deny_all)  # gate unused
    fh = runner.establish("10.5.0.12", kind=SessionKind.SHELL, opened_by="distcc_exec")
    assert fh is not None and fh.ok
    assert fh.session.status is SessionStatus.ACTIVE
    assert fh.proof["whoami"] == "root" and fh.proof["hostname"] == "metasploitable"
    assert fh.evidence  # proof-of-impact captured as audit evidence
    actions = [e.action for e in audit.entries()]
    assert "action.authorized" in actions  # no human at Tier 1
    assert "c2.session.opened" in actions and "c2.foothold.proof" in actions
    assert "gate.request" not in actions
    # exactly the bounded proof commands ran — nothing else
    assert [c[1] for c in backend.commands] == ["id", "whoami", "hostname"]


def test_foothold_gated_and_approved_at_tier0() -> None:
    backend = MockC2Backend(_PROOF)
    runner, mgr, audit = _runner(_scope(tier=0), backend, responder=approve_all())
    fh = runner.establish("10.5.0.12")
    assert fh is not None and fh.ok
    assert "gate.request" in [e.action for e in audit.entries()]  # human in the loop


def test_foothold_gate_denied_opens_no_session() -> None:
    backend = MockC2Backend(_PROOF)
    runner, mgr, audit = _runner(_scope(tier=0), backend, responder=deny_all)
    fh = runner.establish("10.5.0.12")
    assert fh is None
    assert mgr.sessions() == []  # nothing registered
    assert backend.commands == []  # no proof command reached a host
    assert "c2.foothold.denied" in [e.action for e in audit.entries()]


def test_foothold_out_of_scope_refused() -> None:
    runner, _, _ = _runner(_scope(tier=1), MockC2Backend(_PROOF))
    with pytest.raises(ScopeViolationError):
        runner.establish("8.8.8.8")  # not in 10.5.0.0/24


def test_kill_switch_blocks_foothold() -> None:
    ks = KillSwitch()
    ks.trip(reason="operator halt")
    runner, mgr, _ = _runner(_scope(tier=1), MockC2Backend(_PROOF), kill=ks)
    with pytest.raises(StopConditionReached):
        runner.establish("10.5.0.12")
    assert mgr.sessions() == []


def test_dead_backend_yields_unproven_foothold() -> None:
    backend = MockC2Backend(_PROOF, alive=False)
    runner, mgr, audit = _runner(_scope(tier=1), backend)
    fh = runner.establish("10.5.0.12")
    assert fh is not None and not fh.ok
    assert fh.proof == {} and backend.commands == []
    assert "c2.foothold.dead" in [e.action for e in audit.entries()]


# --- teardown -------------------------------------------------------------------


def test_teardown_closes_sessions_and_transport() -> None:
    backend = MockC2Backend(_PROOF)
    runner, mgr, _ = _runner(_scope(tier=1), backend)
    fh1 = runner.establish("10.5.0.12")
    fh2 = runner.establish("10.5.0.13")
    assert len(mgr.sessions(active_only=True)) == 2
    assert runner.teardown() == 2
    assert mgr.sessions(active_only=True) == []  # bookkeeping closed
    assert set(backend.closed) == {fh1.session.id, fh2.session.id}  # transports released
