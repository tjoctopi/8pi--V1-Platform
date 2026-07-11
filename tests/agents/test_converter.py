"""Converter tests — proposes remediations (propose-only) + gated apply."""

from __future__ import annotations

from pathlib import Path

import pytest

from attack_engine.agents.context import AgentContext
from attack_engine.agents.loader import build_agent, load_spec
from attack_engine.governance.audit import AuditLog
from attack_engine.governance.gates import HumanGate, approve_all, deny_all
from attack_engine.knowledge.store import KnowledgeStore
from attack_engine.schemas import Scope
from attack_engine.schemas.findings import Finding, FindingState, Priority
from attack_engine.schemas.remediation import RemediationKind, RemediationStatus
from attack_engine.toolrunner.registry import default_registry
from attack_engine.toolrunner.runner import ToolRunner
from attack_engine.toolrunner.sandbox import NoopSandbox

SPECS = Path(__file__).resolve().parents[2] / "src/attack_engine/agents/specs"


@pytest.fixture
def scope() -> Scope:
    return Scope(engagement_id="engagement-range", allowed_cidrs=("10.5.0.0/24",),
                 authorized_by="t@8pi.ai", signature="sig")


@pytest.fixture
def audit() -> AuditLog:
    return AuditLog()


def _ctx(scope, audit, responder) -> AgentContext:
    store = KnowledgeStore(scope.engagement_id)
    runner = ToolRunner(scope, registry=default_registry(), audit=audit, sandbox=NoopSandbox())
    return AgentContext(scope=scope, tool_runner=runner, store=store, audit=audit,
                        gate=HumanGate(audit, responder=responder))


def _confirmed_cve(store) -> Finding:
    f = store.propose_finding(Finding(
        engagement_id="engagement-range", asset="10.5.0.10", service="Apache httpd/2.4.49",
        type="CVE-2021-41773", on_kev=True, exploit_prob=0.95, priority=Priority.PATCH_IMMEDIATELY,
        metadata={"cvss": 9.8, "port": 80}))
    store.promote_finding(f.id, FindingState.VERIFIED, verified_by="cve_interval_match_v1")
    return store.promote_finding(f.id, FindingState.CONFIRMED)


def test_proposes_patch_for_confirmed_cve(scope, audit) -> None:
    ctx = _ctx(scope, audit, approve_all())
    _confirmed_cve(ctx.store)
    build_agent(load_spec(SPECS / "converter.yaml"), ctx, default_registry()).run([])
    rems = ctx.store.remediations()
    assert len(rems) == 1
    assert rems[0].kind is RemediationKind.PATCH
    assert rems[0].status is RemediationStatus.PROPOSED  # propose-only
    assert "Upgrade" in rems[0].title
    assert "remediation.propose" in [e.action for e in audit.entries()]


def test_does_not_duplicate_remediations(scope, audit) -> None:
    ctx = _ctx(scope, audit, approve_all())
    _confirmed_cve(ctx.store)
    conv = build_agent(load_spec(SPECS / "converter.yaml"), ctx, default_registry())
    conv.run([])
    conv.run([])  # second pass must not add a second proposal
    assert len(ctx.store.remediations()) == 1


def test_apply_requires_gate_and_marks_applied(scope, audit) -> None:
    ctx = _ctx(scope, audit, approve_all("sec-lead"))
    _confirmed_cve(ctx.store)
    conv = build_agent(load_spec(SPECS / "converter.yaml"), ctx, default_registry())
    conv.run([])
    rem = ctx.store.remediations()[0]
    applied = conv.apply(rem)
    assert applied.status is RemediationStatus.APPLIED
    assert applied.applied_by == "converter"
    actions = [e.action for e in audit.entries()]
    assert "gate.approved" in actions and "fix.apply" in actions


def test_apply_denied_leaves_proposed(scope, audit) -> None:
    ctx = _ctx(scope, audit, deny_all)
    _confirmed_cve(ctx.store)
    conv = build_agent(load_spec(SPECS / "converter.yaml"), ctx, default_registry())
    conv.run([])
    rem = ctx.store.remediations()[0]
    result = conv.apply(rem)
    assert result.status is RemediationStatus.PROPOSED  # unchanged — fail closed
    assert "gate.denied" in [e.action for e in audit.entries()]


def test_roe_forces_gate_even_when_spec_omits_it(scope, audit) -> None:
    """A spec cannot downgrade governance: the RoE gates apply_fix regardless."""

    from attack_engine.schemas.agentspec import Guardrails

    ctx = _ctx(scope, audit, deny_all)  # scope.roe gates apply_fix by default
    _confirmed_cve(ctx.store)
    # A spec that deliberately omits apply_fix from its own gate list.
    downgraded = load_spec(SPECS / "converter.yaml").model_copy(
        update={"guardrails": Guardrails(require_gate_before=())}
    )
    conv = build_agent(downgraded, ctx, default_registry())
    conv.run([])
    result = conv.apply(ctx.store.remediations()[0])
    # The human-signed RoE still forced the gate → denied → nothing applied.
    assert result.status is RemediationStatus.PROPOSED
    assert "gate.denied" in [e.action for e in audit.entries()]
