"""Fixtures wiring a full in-process engine for agent tests."""

from __future__ import annotations

import pytest

from attack_engine.agents.context import AgentContext
from attack_engine.config import Settings
from attack_engine.eventbus.memory import InMemoryEventBus
from attack_engine.gateway.provider import MockProvider
from attack_engine.gateway.router import ModelGateway
from attack_engine.governance.audit import AuditLog
from attack_engine.knowledge.store import KnowledgeStore
from attack_engine.schemas import Scope
from attack_engine.toolrunner.registry import default_registry
from attack_engine.toolrunner.runner import ToolRunner

# Reuse the tool-output fixtures + FakeSandbox from the toolrunner tests.
from tests.toolrunner.conftest import FFUF_JSON, NMAP_XML, FakeSandbox


@pytest.fixture
def scope() -> Scope:
    return Scope(
        engagement_id="engagement-1723",
        allowed_cidrs=("10.0.4.0/24",),
        allowed_hosts=("juice.local",),
        authorized_by="tester@8pi.ai",
        signature="sig",
    )


@pytest.fixture
def audit() -> AuditLog:
    return AuditLog()


@pytest.fixture
def bus() -> InMemoryEventBus:
    return InMemoryEventBus()


@pytest.fixture
def fake_sandbox() -> FakeSandbox:
    from attack_engine.toolrunner.sandbox import SandboxResult

    sb = FakeSandbox()
    sb.set_response("nmap", SandboxResult(0, NMAP_XML, b"", 0.05, "fake"))
    sb.set_response("ffuf", SandboxResult(0, FFUF_JSON, b"", 0.05, "fake"))
    return sb


@pytest.fixture
def gateway(audit: AuditLog) -> ModelGateway:
    settings = Settings(model_mock=True)
    return ModelGateway(settings=settings, provider=MockProvider(), audit=audit)


@pytest.fixture
def ctx(scope, audit, bus, fake_sandbox, gateway) -> AgentContext:
    store = KnowledgeStore(scope.engagement_id, event_bus=bus)
    runner = ToolRunner(
        scope,
        registry=default_registry(),
        audit=audit,
        sandbox=fake_sandbox,
        event_bus=bus,
        actor="surface_mapper",
    )
    return AgentContext(
        scope=scope,
        tool_runner=runner,
        store=store,
        audit=audit,
        gateway=gateway,
        event_bus=bus,
    )
