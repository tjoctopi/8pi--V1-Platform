"""Sprint 0 exit-gate acceptance test.

    "A scoped recon runs end-to-end, every call audited, producing a verified,
     deduped asset inventory with zero false positives on the range."

This test encodes that gate against the in-process engine with the ground-truth
nmap/ffuf fixtures, so regressions in any spine component fail here loudly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from attack_engine.agents.loader import load_spec
from attack_engine.config import (
    AuditBackend,
    EventBusBackend,
    SandboxBackend,
    Settings,
)
from attack_engine.engine import Engine
from attack_engine.errors import ScopeViolationError
from attack_engine.eventbus.memory import InMemoryEventBus
from attack_engine.gateway.provider import MockProvider
from attack_engine.gateway.router import ModelGateway
from attack_engine.governance.audit import AuditLog
from attack_engine.governance.audit_backends import MemoryAuditBackend
from attack_engine.schemas import RateLimit, RulesOfEngagement, Scope
from attack_engine.schemas.findings import FindingState
from attack_engine.toolrunner.registry import default_registry
from attack_engine.toolrunner.sandbox import SandboxResult
from tests.toolrunner.conftest import FFUF_JSON, NMAP_XML, FakeSandbox

SPEC = Path(__file__).resolve().parents[1] / "src/attack_engine/agents/specs/surface_mapper.yaml"


@pytest.fixture
def engine() -> Engine:
    settings = Settings(
        env="test",
        model_mock=True,
        audit_backend=AuditBackend.MEMORY,
        eventbus_backend=EventBusBackend.MEMORY,
        sandbox_backend=SandboxBackend.NOOP,
    )
    sb = FakeSandbox()
    sb.set_response("nmap", SandboxResult(0, NMAP_XML, b"", 0.05, "fake"))
    sb.set_response("ffuf", SandboxResult(0, FFUF_JSON, b"", 0.05, "fake"))
    audit = AuditLog(MemoryAuditBackend())
    return Engine(
        settings,
        audit=audit,
        event_bus=InMemoryEventBus(),
        gateway=ModelGateway(settings=settings, provider=MockProvider(), audit=audit),
        sandbox=sb,
        registry=default_registry(),
    )


@pytest.fixture
def range_scope() -> Scope:
    return Scope(
        engagement_id="engagement-range",
        allowed_cidrs=("10.5.0.0/24",),
        roe=RulesOfEngagement(
            default_rate_limit=RateLimit(requests_per_sec=100, burst=10)
        ),
        authorized_by="tester@8pi.ai",
        signature="sig",
    )


def test_sprint0_exit_gate(engine: Engine, range_scope: Scope) -> None:
    engagement = engine.engagement(range_scope)
    spec = load_spec(SPEC)

    # --- 1. A scoped recon runs end to end ---
    report = engagement.run_agent(spec, ["10.5.0.10"])
    assert report.stopped_reason == "completed"

    # --- 2. Produces an asset inventory ---
    assets = engagement.store.assets()
    assert len(assets) == 1
    asset = assets[0]

    # --- 3. Zero false positives: only genuinely OPEN ports appear ---
    # The nmap fixture reports 22 as CLOSED; it must never become a service.
    ports = {s.port for s in asset.services}
    assert ports == {80, 3306}
    assert 22 not in ports

    # --- 4. Deduped: re-running recon must NOT duplicate assets or findings ---
    findings_after_first = len(engagement.store.findings())
    engagement.run_agent(spec, ["10.5.0.10"])
    assert len(engagement.store.assets()) == 1  # merged, not duplicated
    assert len(engagement.store.findings()) == findings_after_first  # deduped

    # --- 5. Nothing confirmed by recon (propose/verify — rule #1) ---
    assert engagement.store.findings(FindingState.CONFIRMED) == []
    assert all(f.state is FindingState.PROPOSED for f in engagement.store.findings())

    # --- 6. Every call audited, and the chain is intact ---
    actions = [e.action for e in engine.audit.entries("engagement-range")]
    tools_run = {
        e.payload.get("tool") for e in engine.audit.entries("engagement-range")
        if e.action == "tool.run"
    }
    assert {"nmap", "ffuf"} <= tools_run  # recon drove (at least) nmap + ffuf
    assert "engagement.start" in actions
    assert engine.audit.verify() is True

    # --- 7. The scope boundary refuses out-of-scope targets (before any tool) ---
    with pytest.raises(ScopeViolationError):
        engagement.tool_runner.run("nmap", "8.8.8.8")
    # ...and that refusal is itself audited without breaking the chain.
    assert "tool.refused" in [e.action for e in engine.audit.entries("engagement-range")]
    assert engine.audit.verify() is True
