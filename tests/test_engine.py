"""Engine composition-root tests: wiring + a full scoped engagement."""

from __future__ import annotations

from pathlib import Path

import pytest

from attack_engine.config import (
    AuditBackend,
    EventBusBackend,
    SandboxBackend,
    Settings,
)
from attack_engine.engine import Engine, load_scope
from attack_engine.errors import AttackEngineError
from attack_engine.gateway.provider import MockProvider
from attack_engine.gateway.router import ModelGateway
from attack_engine.governance.audit import AuditLog
from attack_engine.governance.audit_backends import MemoryAuditBackend
from attack_engine.schemas import Scope
from attack_engine.toolrunner.registry import default_registry
from tests.toolrunner.conftest import FFUF_JSON, NMAP_XML, FakeSandbox

SPECS_DIR = Path(__file__).resolve().parents[1] / "src/attack_engine/agents/specs"


@pytest.fixture
def test_settings() -> Settings:
    return Settings(
        env="test",
        model_mock=True,
        audit_backend=AuditBackend.MEMORY,
        eventbus_backend=EventBusBackend.MEMORY,
        sandbox_backend=SandboxBackend.NOOP,
    )


@pytest.fixture
def engine(test_settings: Settings) -> Engine:
    from attack_engine.eventbus.memory import InMemoryEventBus
    from attack_engine.toolrunner.sandbox import SandboxResult

    sb = FakeSandbox()
    sb.set_response("nmap", SandboxResult(0, NMAP_XML, b"", 0.05, "fake"))
    sb.set_response("ffuf", SandboxResult(0, FFUF_JSON, b"", 0.05, "fake"))
    audit = AuditLog(MemoryAuditBackend())
    return Engine(
        test_settings,
        audit=audit,
        event_bus=InMemoryEventBus(),
        gateway=ModelGateway(settings=test_settings, provider=MockProvider(), audit=audit),
        sandbox=sb,
        registry=default_registry(),
    )


@pytest.fixture
def range_scope() -> Scope:
    return Scope(
        engagement_id="engagement-range",
        allowed_cidrs=("10.5.0.0/24",),
        authorized_by="tester@8pi.ai",
        signature="sig",
    )


def test_engagement_records_start_in_audit(engine: Engine, range_scope: Scope) -> None:
    engine.engagement(range_scope)
    actions = [e.action for e in engine.audit.entries("engagement-range")]
    assert "engagement.start" in actions


def test_full_scoped_recon_engagement(engine: Engine, range_scope: Scope) -> None:
    from attack_engine.agents.loader import load_spec

    engagement = engine.engagement(range_scope)
    spec = load_spec(SPECS_DIR / "surface_mapper.yaml")
    report = engagement.run_agent(spec, ["10.5.0.10"])

    assert report.assets_found == 1
    assert report.findings_proposed >= 2
    assert engagement.store.assets()[0].address == "10.5.0.10"
    # Every action audited and the chain is intact — the Sprint 0 exit gate.
    assert engine.audit.verify() is True


def test_unsigned_scope_refused_when_required(engine: Engine) -> None:
    unsigned = Scope(engagement_id="engagement-x", allowed_cidrs=("10.5.0.0/24",))
    with pytest.raises(AttackEngineError, match="not signed"):
        engine.engagement(unsigned, require_signed=True)


def test_from_settings_falls_back_to_mock(test_settings: Settings) -> None:
    engine = Engine.from_settings(test_settings)
    assert engine.gateway.provider_name == "mock"
    assert engine.sandbox.name == "noop"


def test_load_scope_from_example_file() -> None:
    example = Path(__file__).resolve().parents[1] / "examples/engagement-range.scope.yaml"
    scope = load_scope(example)
    assert scope.engagement_id == "engagement-range"
    assert "10.5.0.0/24" in scope.allowed_cidrs
