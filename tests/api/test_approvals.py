"""Human-approval broker tests (Slice 3) — gated actions over HTTP.

The broker's :meth:`responder` blocks the engine worker thread until a human
resolves it; these tests drive it from a second thread, exactly as the live
system does (engine worker blocks; HTTP handler resolves).
"""

from __future__ import annotations

import threading
import time

import pytest

from attack_engine.api.adapter import EngineAdapter, engagement_id_for, scope_from_roe
from attack_engine.api.approvals import ApprovalBroker
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
from attack_engine.governance.gates import GateDecision, GateRequest
from attack_engine.toolrunner.registry import default_registry
from tests.toolrunner.conftest import FakeSandbox


def _request(eid: str = "eng-appr-0001", gate: str = "exploit_confirm") -> GateRequest:
    return GateRequest(
        id="gate-abc", engagement_id=eid, gate=gate, requested_by="exploit-confirmer",
        target="10.5.0.12", summary="confirm RCE on 10.5.0.12",
        context={"tool": "metasploit", "technique": {"id": "T1190"}}, ts="2026-07-18T00:00:00Z",
    )


def test_broker_approve_unblocks_with_approved() -> None:
    broker = ApprovalBroker()
    result: dict[str, object] = {}

    def worker() -> None:
        result["resp"] = broker.responder(_request())

    t = threading.Thread(target=worker)
    t.start()
    # Wait for the request to be parked, then approve it.
    for _ in range(100):
        if broker.pending("eng-appr-0001"):
            break
        time.sleep(0.01)
    pend = broker.pending("eng-appr-0001")
    assert len(pend) == 1
    assert pend[0]["action"]["tool_id"] == "metasploit"
    assert pend[0]["action"]["technique"]["id"] == "T1190"
    assert broker.resolve("gate-abc", approved=True, approver="boss@acme.example")
    t.join(timeout=2)
    assert result["resp"].decision is GateDecision.APPROVED  # type: ignore[union-attr]
    assert result["resp"].approver == "boss@acme.example"  # type: ignore[union-attr]
    # It moves from pending → resolved history.
    assert broker.pending("eng-appr-0001") == []
    hist = broker.approvals("eng-appr-0001", status="approved")
    assert len(hist) == 1 and hist[0]["approver"] == "boss@acme.example"


def test_broker_deny() -> None:
    broker = ApprovalBroker()
    out: dict[str, object] = {}
    t = threading.Thread(target=lambda: out.__setitem__("r", broker.responder(_request())))
    t.start()
    for _ in range(100):
        if broker.pending("eng-appr-0001"):
            break
        time.sleep(0.01)
    broker.resolve("gate-abc", approved=False, approver="boss@x", reason="too risky")
    t.join(timeout=2)
    assert out["r"].decision is GateDecision.DENIED  # type: ignore[union-attr]
    assert out["r"].reason == "too risky"  # type: ignore[union-attr]


def test_broker_times_out_failing_closed() -> None:
    broker = ApprovalBroker(timeout_sec=0)  # no wait → immediate fail-closed
    resp = broker.responder(_request())
    assert resp.decision is GateDecision.DENIED
    assert "timed out" in resp.reason


def test_resolve_unknown_id_returns_false() -> None:
    broker = ApprovalBroker()
    assert broker.resolve("nope", approved=True, approver="x") is False


# ── adapter integration: a real gated action routes to the broker ─────────────

def _adapter() -> EngineAdapter:
    settings = Settings(
        env="test", model_mock=True,
        audit_backend=AuditBackend.MEMORY, eventbus_backend=EventBusBackend.MEMORY,
        sandbox_backend=SandboxBackend.NOOP,
    )
    audit = AuditLog(MemoryAuditBackend())
    engine = Engine(
        settings, audit=audit, event_bus=InMemoryEventBus(),
        gateway=ModelGateway(settings=settings, provider=MockProvider(), audit=audit),
        sandbox=FakeSandbox(), registry=default_registry(),
    )
    return EngineAdapter(engine)


def test_signed_engagement_gate_routes_to_console_and_audits() -> None:
    adapter = _adapter()
    scope = scope_from_roe(
        "appr-live", {"scope_allowlist": ["10.5.0.0/24"], "max_intensity": "exploit"},
        authorized_by="ciso@x", signature="real-sig",
    )
    eng = adapter.open(scope)

    outcome: dict[str, object] = {}

    def worker() -> None:
        # A gated high-impact action consults the human gate → broker → blocks.
        resp = eng.context.gate.require(
            engagement_id=scope.engagement_id, gate="exploit_confirm",
            requested_by="exploit-confirmer", target="10.5.0.12",
            summary="confirm RCE",
        )
        outcome["approver"] = resp.approver

    t = threading.Thread(target=worker)
    t.start()
    approval_id = None
    for _ in range(200):
        pend = adapter.approvals("appr-live", status="pending")
        if pend:
            approval_id = pend[0]["id"]
            break
        time.sleep(0.01)
    assert approval_id is not None
    assert adapter.pending_approvals("appr-live") == 1
    assert adapter.resolve_approval(approval_id, approved=True, approver="boss@x")
    t.join(timeout=2)
    assert outcome["approver"] == "boss@x"
    # The gate request + approval are on the real audit chain.
    actions = [e.action for e in adapter.engine.audit.entries(
        engagement_id=engagement_id_for("appr-live"))]
    assert "gate.request" in actions
    assert "gate.approved" in actions


def test_test_authorization_stays_frictionless() -> None:
    """A one-click test scope must NOT route gates to the broker (auto-approve)."""

    settings = Settings(
        env="test", model_mock=True, allow_test_authorization=True,
        audit_backend=AuditBackend.MEMORY, eventbus_backend=EventBusBackend.MEMORY,
        sandbox_backend=SandboxBackend.NOOP,
    )
    audit = AuditLog(MemoryAuditBackend())
    engine = Engine(
        settings, audit=audit, event_bus=InMemoryEventBus(),
        gateway=ModelGateway(settings=settings, provider=MockProvider(), audit=audit),
        sandbox=FakeSandbox(), registry=default_registry(),
    )
    adapter = EngineAdapter(engine)
    eng = adapter.open_for_testing("test-fric", ["10.5.0.12"])
    # Gate resolves immediately (auto-approve), nothing parks for a human.
    resp = eng.context.gate.require(
        engagement_id=eng.scope.engagement_id, gate="exploit_confirm",
        requested_by="x", target="10.5.0.12", summary="s",
    )
    assert resp.decision is GateDecision.APPROVED
    assert adapter.pending_approvals("test-fric") == 0


@pytest.mark.parametrize("approved", [True, False])
def test_pending_count_and_history(approved: bool) -> None:
    broker = ApprovalBroker()
    t = threading.Thread(target=lambda: broker.responder(_request()))
    t.start()
    for _ in range(100):
        if broker.pending_count("eng-appr-0001"):
            break
        time.sleep(0.01)
    assert broker.pending_count("eng-appr-0001") == 1
    broker.resolve("gate-abc", approved=approved, approver="a@x")
    t.join(timeout=2)
    assert broker.pending_count("eng-appr-0001") == 0
    status = "approved" if approved else "denied"
    assert broker.approvals("eng-appr-0001", status=status)
