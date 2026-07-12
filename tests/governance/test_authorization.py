"""Engagement-boundary authorization + kill-switch tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from attack_engine.agents.context import AgentContext
from attack_engine.agents.loader import build_agent, load_spec
from attack_engine.errors import GateDeniedError, StopConditionReached
from attack_engine.governance.audit import AuditLog
from attack_engine.governance.authorization import (
    AuthorizationDecision,
    AuthorizationPolicy,
    KillSwitch,
)
from attack_engine.governance.gates import HumanGate, approve_all, deny_all
from attack_engine.knowledge.store import KnowledgeStore
from attack_engine.schemas import RulesOfEngagement, Scope
from attack_engine.toolrunner.registry import default_registry
from attack_engine.toolrunner.runner import ToolRunner

_SPECS_DIR = Path(__file__).resolve().parents[2] / "src/attack_engine/agents/specs"


def _scope(*, tier: int, authorized=frozenset(), signed: bool = True,
           high_impact=None, expires=None) -> Scope:
    roe_kwargs: dict = {"autonomy_tier": tier, "authorized_techniques": authorized}
    if high_impact is not None:
        roe_kwargs["high_impact_actions"] = high_impact
    return Scope(
        engagement_id="engagement-auth",
        allowed_cidrs=("10.5.0.0/24",),
        roe=RulesOfEngagement(**roe_kwargs),
        authorized_by="lead@8pi.ai" if signed else None,
        signature="signed" if signed else None,
        expires_at=expires,
    )


# --- AuthorizationPolicy ------------------------------------------------------

def test_tier0_always_gates() -> None:
    pol = AuthorizationPolicy(_scope(tier=0, authorized=frozenset({"exploit_confirm"})))
    assert pol.decide("exploit_confirm") is AuthorizationDecision.GATE


def test_tier1_authorized_action_runs_autonomously() -> None:
    pol = AuthorizationPolicy(_scope(tier=1, authorized=frozenset({"exploit_confirm"})))
    assert pol.decide("exploit_confirm") is AuthorizationDecision.AUTONOMOUS


def test_tier1_authorized_by_technique() -> None:
    pol = AuthorizationPolicy(_scope(tier=1, authorized=frozenset({"T1190"})))
    assert pol.decide("exploit_confirm", technique="T1190") is AuthorizationDecision.AUTONOMOUS


def test_high_impact_always_gates_even_if_listed() -> None:
    # apply_fix is high-impact by default; listing it must not auto-authorize it.
    pol = AuthorizationPolicy(_scope(tier=2, authorized=frozenset({"apply_fix", "exploit_confirm"})))
    assert pol.decide("apply_fix") is AuthorizationDecision.GATE
    assert pol.decide("exploit_confirm") is AuthorizationDecision.AUTONOMOUS


def test_off_allowlist_gates() -> None:
    pol = AuthorizationPolicy(_scope(tier=1, authorized=frozenset({"exploit_confirm"})))
    assert pol.decide("containment") is AuthorizationDecision.GATE  # not listed


def test_unsigned_scope_fails_safe_to_gate() -> None:
    pol = AuthorizationPolicy(_scope(tier=1, authorized=frozenset({"exploit_confirm"}), signed=False))
    assert pol.decide("exploit_confirm") is AuthorizationDecision.GATE


def test_expired_scope_fails_safe_to_gate() -> None:
    past = datetime.now(UTC) - timedelta(days=1)
    pol = AuthorizationPolicy(
        _scope(tier=1, authorized=frozenset({"exploit_confirm"}), expires=past))
    assert pol.decide("exploit_confirm") is AuthorizationDecision.GATE


# --- KillSwitch ---------------------------------------------------------------

def test_kill_switch_trips() -> None:
    ks = KillSwitch()
    assert ks.tripped is False
    ks.trip(reason="operator halt", by="ciso")
    assert ks.tripped is True
    assert ks.reason == "operator halt" and ks.tripped_by == "ciso"


# --- agent-level behaviour ----------------------------------------------------

def _ctx(scope: Scope, *, responder, kill_switch=None) -> AgentContext:
    audit = AuditLog()
    runner = ToolRunner(scope, registry=default_registry(), audit=audit)
    return AgentContext(
        scope=scope, tool_runner=runner, store=KnowledgeStore(scope.engagement_id),
        audit=audit, gate=HumanGate(audit, responder=responder), kill_switch=kill_switch,
    )


def _agent(ctx):
    return build_agent(load_spec(_SPECS_DIR / "exploit_confirmer.yaml"), ctx, default_registry())


def test_agent_runs_authorized_action_without_a_gate() -> None:
    # Tier-1 signed engagement pre-authorizing exploit_confirm: require_gate must
    # NOT consult the human gate (deny_all would raise if it did).
    ctx = _ctx(_scope(tier=1, authorized=frozenset({"exploit_confirm"})), responder=deny_all)
    _agent(ctx).require_gate("exploit_confirm", target="10.5.0.10", technique="T1190")
    actions = [e.action for e in ctx.audit.entries()]
    assert "action.authorized" in actions          # recorded as engagement-authorized
    assert "gate.request" not in actions            # no human was consulted


def test_agent_gates_when_not_authorized() -> None:
    # Same action, but not on the allowlist → must gate (deny_all → denied).
    ctx = _ctx(_scope(tier=1, authorized=frozenset({"lateral_movement"})), responder=deny_all)
    with pytest.raises(GateDeniedError):
        _agent(ctx).require_gate("exploit_confirm", target="10.5.0.10")


def test_tier0_still_gates_at_agent_level() -> None:
    ctx = _ctx(_scope(tier=0, authorized=frozenset({"exploit_confirm"})), responder=approve_all())
    _agent(ctx).require_gate("exploit_confirm", target="10.5.0.10")
    actions = [e.action for e in ctx.audit.entries()]
    assert "gate.request" in actions and "gate.approved" in actions  # human in the loop


def test_kill_switch_halts_agent() -> None:
    ks = KillSwitch()
    ks.trip(reason="operator halt")
    ctx = _ctx(_scope(tier=1, authorized=frozenset({"exploit_confirm"})),
               responder=approve_all(), kill_switch=ks)
    with pytest.raises(StopConditionReached):
        _agent(ctx).require_gate("exploit_confirm", target="10.5.0.10")
