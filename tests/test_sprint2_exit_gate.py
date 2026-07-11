"""Sprint 2 exit-gate acceptance test.

    "Full purple-team loop runs autonomously in the sandbox — plan → attack →
     confirm → propose fix → re-test → report — with every real-world-effect
     action gated and audited."

The Orchestrator drives the loop end to end against a scripted range. A separate
gated ``close_loop`` applies an approved fix and re-tests: we exercise both the
fix-holds path (remediation verified) and the fix-fails path (escalated).
"""

from __future__ import annotations

import pytest

from attack_engine.config import (
    AuditBackend,
    EventBusBackend,
    SandboxBackend,
    Settings,
)
from attack_engine.engine import Engine
from attack_engine.eventbus.memory import InMemoryEventBus
from attack_engine.gateway.provider import MockProvider
from attack_engine.gateway.router import ModelGateway
from attack_engine.governance.audit import AuditLog
from attack_engine.governance.audit_backends import MemoryAuditBackend
from attack_engine.governance.gates import approve_all
from attack_engine.schemas import RateLimit, RulesOfEngagement, Scope
from attack_engine.schemas.events import EventType
from attack_engine.schemas.findings import FindingState, Priority
from attack_engine.schemas.remediation import RemediationStatus
from attack_engine.toolrunner.registry import default_registry
from attack_engine.toolrunner.sandbox import Sandbox, SandboxResult, SandboxSpec

# nmap: an internet-facing host running the vulnerable Apache + a web app port.
NMAP_VULN = b"""<?xml version="1.0"?>
<nmaprun><host><status state="up"/>
 <address addr="10.5.0.10" addrtype="ipv4"/>
 <ports>
  <port protocol="tcp" portid="80"><state state="open"/>
    <service name="http" product="Apache httpd" version="2.4.49"/></port>
  <port protocol="tcp" portid="3000"><state state="open"/>
    <service name="http" product="Node.js Express"/></port>
 </ports></host></nmaprun>
"""
# nmap after remediation: Apache upgraded to 2.4.51 (fixed).
NMAP_FIXED = NMAP_VULN.replace(b"2.4.49", b"2.4.51")

NUCLEI_SQLI = (
    b'{"template-id":"sqli-detection","info":{"name":"SQL Injection","severity":"high"},'
    b'"matched-at":"http://10.5.0.10:3000/rest/products/search?q=apples","type":"http"}\n'
)
SQLMAP_INJECTABLE = b"Parameter: q (GET)\n    Type: boolean-based blind\n"


class RangeSandbox(Sandbox):
    """Scripts the whole loop; ``remediated`` flips targets to their fixed state."""

    name = "range"

    def __init__(self) -> None:
        self.calls: list[SandboxSpec] = []
        self.remediated = False

    def run(self, spec: SandboxSpec) -> SandboxResult:
        self.calls.append(spec)
        b = spec.argv[0] if spec.argv else ""
        if b == "nmap":
            xml = NMAP_FIXED if self.remediated else NMAP_VULN
            return SandboxResult(0, xml, b"", 0.05, self.name)
        if b == "nuclei":
            return SandboxResult(0, NUCLEI_SQLI, b"", 0.1, self.name)
        if b == "sqlmap":
            return SandboxResult(0, SQLMAP_INJECTABLE, b"", 0.2, self.name)
        if b == "curl":
            url = spec.argv[-1]
            injectable = "/rest/products/search" in url
            true_cond = "%3D%271" in url
            # After remediation the endpoint no longer leaks a differential.
            size = 128 if self.remediated else (5120 if (injectable and true_cond) else 128)
            return SandboxResult(0, f"HTTP:200 SIZE:{size} TIME:0.01".encode(), b"", 0.01, self.name)
        return SandboxResult(0, b"", b"", 0.01, self.name)


def _make_engine(sandbox: RangeSandbox) -> Engine:
    settings = Settings(
        env="test", model_mock=True,
        audit_backend=AuditBackend.MEMORY,
        eventbus_backend=EventBusBackend.MEMORY,
        sandbox_backend=SandboxBackend.NOOP,
    )
    audit = AuditLog(MemoryAuditBackend())
    return Engine(
        settings,
        audit=audit,
        event_bus=InMemoryEventBus(),
        gateway=ModelGateway(settings=settings, provider=MockProvider(), audit=audit),
        sandbox=sandbox,
        registry=default_registry(),
        gate_responder=approve_all("security-lead"),
    )


@pytest.fixture
def scope() -> Scope:
    return Scope(
        engagement_id="engagement-range",
        allowed_cidrs=("10.5.0.0/24",),
        roe=RulesOfEngagement(default_rate_limit=RateLimit(requests_per_sec=1000, burst=1000)),
        authorized_by="tester@8pi.ai", signature="sig",
    )


def _run_full_loop(scope: Scope):
    sandbox = RangeSandbox()
    engine = _make_engine(sandbox)
    engagement = engine.engagement(scope)
    blue = engine.blue_sentry(scope)
    orch = engagement.orchestrator(blue_sentry=blue)
    result = orch.run(["10.5.0.10"], goal="assess")
    return engine, engagement, orch, sandbox, blue, result


def test_full_loop_runs_and_confirms(scope: Scope) -> None:
    engine, engagement, orch, sandbox, blue, result = _run_full_loop(scope)
    store = engagement.store

    # --- plan → the canonical phase DAG executed in order ---
    assert result.plan.phase_names()[0] == "recon"
    assert result.plan.phase_names()[-1] == "report"
    phase_events = [
        e.payload["phase"] for e in engine.event_bus.history(engagement_id=scope.engagement_id)
        if e.event is EventType.PHASE_COMPLETED
    ]
    assert phase_events[0] == "recon" and "convert" in phase_events

    # --- confirm → the vulnerable Apache CVE and the SQLi are both CONFIRMED ---
    confirmed = store.findings(FindingState.CONFIRMED)
    types = {f.type for f in confirmed}
    assert any(t.startswith("CVE-2021-417") for t in types)
    assert any(t.startswith("sqli") for t in types)
    apache = next(f for f in confirmed if f.type == "CVE-2021-41773")
    assert apache.priority is Priority.PATCH_IMMEDIATELY and apache.on_kev

    # --- propose fix → a remediation for every confirmed finding (propose-only) ---
    assert store.remediations()
    assert all(r.status is RemediationStatus.PROPOSED for r in store.remediations())

    # --- report → generated, evidence-linked, chain intact ---
    assert result.report.confirmed
    assert result.report.audit_intact is True
    assert "# Engagement Report" in result.report.to_markdown()

    # --- Blue Sentry ran in parallel: authorized scans classified as noise ---
    assert blue.report.expected_noise > 0
    assert blue.report.alert_count == 0  # nothing out-of-RoE happened

    # --- every real-world-effect action gated + audited; chain intact ---
    actions = [e.action for e in engine.audit.entries()]
    assert "plan.built" in actions
    assert "gate.request" in actions and "gate.approved" in actions  # exploit-confirm gate
    assert "remediation.propose" in actions
    assert engine.audit.verify() is True


def test_autonomous_run_never_applies_a_fix(scope: Scope) -> None:
    """The autonomous loop proposes but must never apply a real-world change."""

    engine, engagement, orch, sandbox, blue, _ = _run_full_loop(scope)
    # No fix was applied: no audit action, no event, no remediation left PROPOSED.
    actions = [e.action for e in engine.audit.entries()]
    assert "fix.apply" not in actions
    events = [
        e.event for e in engine.event_bus.history(engagement_id=scope.engagement_id)
    ]
    assert EventType.FIX_APPLIED not in events
    assert engagement.store.remediations()  # fixes were *proposed*...
    assert all(  # ...but every one is still merely proposed
        r.status is RemediationStatus.PROPOSED for r in engagement.store.remediations()
    )


def test_close_loop_fix_holds(scope: Scope) -> None:
    engine, engagement, orch, sandbox, blue, _ = _run_full_loop(scope)

    # A human/automation applies the fix out-of-band → range is now patched.
    sandbox.remediated = True
    retests = orch.close_loop()

    assert retests, "should have re-tested applied remediations"
    assert all(rt.fixed for rt in retests)  # every fix holds
    # Remediations recorded as verified-fixed; RETEST_PASSED emitted.
    assert all(
        r.status is RemediationStatus.VERIFIED_FIXED
        for r in engagement.store.remediations()
    )
    passed = [e for e in engine.event_bus.history(engagement_id=scope.engagement_id)
              if e.event is EventType.RETEST_PASSED]
    assert passed
    actions = [e.action for e in engine.audit.entries()]
    assert "fix.apply" in actions and "retest" in actions
    assert engine.audit.verify() is True


def test_close_loop_persisted_escalates(scope: Scope) -> None:
    engine, engagement, orch, sandbox, blue, _ = _run_full_loop(scope)

    # No fix applied to the environment → the vulnerabilities persist on re-test.
    retests = orch.close_loop()  # sandbox.remediated stays False

    assert retests
    assert any(not rt.fixed for rt in retests)  # at least one persists
    escalated = [e for e in engine.event_bus.history(engagement_id=scope.engagement_id)
                 if e.event is EventType.FINDING_ESCALATED]
    assert escalated
    assert any(
        r.status is RemediationStatus.PERSISTED for r in engagement.store.remediations()
    )
    assert engine.audit.verify() is True


def test_close_loop_denied_gate_does_not_apply_or_retest(scope: Scope) -> None:
    # Gate DENIES apply_fix → nothing is applied and no re-test runs.
    sandbox = RangeSandbox()
    settings = Settings(env="test", model_mock=True, audit_backend=AuditBackend.MEMORY,
                        eventbus_backend=EventBusBackend.MEMORY, sandbox_backend=SandboxBackend.NOOP)
    audit = AuditLog(MemoryAuditBackend())
    from attack_engine.governance.gates import GateDecision, GateResponse

    def responder(req):  # approve exploit-confirm, deny apply_fix
        if req.gate == "apply_fix":
            return GateResponse(decision=GateDecision.DENIED, reason="change window closed")
        return GateResponse(decision=GateDecision.APPROVED, approver="sec-lead")

    engine = Engine(settings, audit=audit, event_bus=InMemoryEventBus(),
                    gateway=ModelGateway(settings=settings, provider=MockProvider(), audit=audit),
                    sandbox=sandbox, registry=default_registry(), gate_responder=responder)
    engagement = engine.engagement(scope)
    orch = engagement.orchestrator(blue_sentry=engine.blue_sentry(scope))
    orch.run(["10.5.0.10"])
    retests = orch.close_loop()

    assert retests == []  # nothing applied → nothing re-tested
    assert all(r.status is RemediationStatus.PROPOSED for r in engagement.store.remediations())
    assert "gate.denied" in [e.action for e in engine.audit.entries()]
