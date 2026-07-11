"""Human gate tests — real-world-effect actions never proceed unapproved."""

from __future__ import annotations

import pytest

from attack_engine.errors import GateDeniedError
from attack_engine.governance.audit import AuditLog
from attack_engine.governance.gates import (
    GateDecision,
    HumanGate,
    approve_all,
)
from attack_engine.governance.roe import RoEEvaluator
from attack_engine.schemas import Scope


@pytest.fixture
def audit() -> AuditLog:
    return AuditLog()


def test_defaults_to_deny_when_no_responder(audit: AuditLog) -> None:
    gate = HumanGate(audit)  # no responder → fail closed
    with pytest.raises(GateDeniedError):
        gate.require(
            engagement_id="eng-1", gate="exploit_confirm", requested_by="exploiter"
        )


def test_approve_all_lets_action_through(audit: AuditLog) -> None:
    gate = HumanGate(audit, responder=approve_all("alice"))
    resp = gate.require(
        engagement_id="eng-1", gate="exploit_confirm", requested_by="exploiter"
    )
    assert resp.decision is GateDecision.APPROVED
    assert resp.approver == "alice"


def test_request_and_decision_are_both_audited(audit: AuditLog) -> None:
    gate = HumanGate(audit, responder=approve_all("alice"))
    gate.require(engagement_id="eng-1", gate="apply_fix", requested_by="converter")
    actions = [e.action for e in audit.entries("eng-1")]
    assert "gate.request" in actions
    assert "gate.approved" in actions
    assert audit.verify() is True


def test_denial_is_audited_and_raises(audit: AuditLog) -> None:
    from attack_engine.governance.gates import GateResponse

    def deny(_req):
        return GateResponse(decision=GateDecision.DENIED, reason="not in window")

    gate = HumanGate(audit, responder=deny)
    with pytest.raises(GateDeniedError, match="not in window"):
        gate.require(engagement_id="eng-1", gate="containment", requested_by="blue")
    actions = [e.action for e in audit.entries("eng-1")]
    assert "gate.denied" in actions


class TestRoEEvaluator:
    def test_read_only_blocks_mutation(self) -> None:
        scope = Scope(engagement_id="eng-1", allowed_cidrs=("10.0.0.0/24",))
        roe = RoEEvaluator(scope)
        assert roe.allows_mutation(mutating=False) is True
        assert roe.allows_mutation(mutating=True) is False

    def test_gated_actions_default_set(self) -> None:
        scope = Scope(engagement_id="eng-1", allowed_cidrs=("10.0.0.0/24",))
        roe = RoEEvaluator(scope)
        assert roe.requires_gate("exploit_confirm")
        assert roe.requires_gate("apply_fix")
        assert not roe.requires_gate("recon")

    def test_forbidden_tools(self) -> None:
        from attack_engine.schemas import RulesOfEngagement

        scope = Scope(
            engagement_id="eng-1",
            allowed_cidrs=("10.0.0.0/24",),
            roe=RulesOfEngagement(forbidden_tools=frozenset({"metasploit"})),
        )
        roe = RoEEvaluator(scope)
        assert roe.is_tool_forbidden("metasploit")
        assert not roe.is_tool_forbidden("nmap")

    def test_call_budget(self) -> None:
        from attack_engine.schemas import RulesOfEngagement

        scope = Scope(
            engagement_id="eng-1",
            allowed_cidrs=("10.0.0.0/24",),
            roe=RulesOfEngagement(max_total_tool_calls=2),
        )
        roe = RoEEvaluator(scope)
        assert roe.within_call_budget(0)
        assert roe.within_call_budget(1)
        assert not roe.within_call_budget(2)
