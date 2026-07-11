"""Multi-engagement manager tests — RBAC isolation between tenants."""

from __future__ import annotations

import pytest

from attack_engine.config import (
    AuditBackend,
    EventBusBackend,
    SandboxBackend,
    Settings,
)
from attack_engine.engine import Engine
from attack_engine.errors import AuthorizationError
from attack_engine.eventbus.memory import InMemoryEventBus
from attack_engine.gateway.provider import MockProvider
from attack_engine.gateway.router import ModelGateway
from attack_engine.governance.audit import AuditLog
from attack_engine.governance.audit_backends import MemoryAuditBackend
from attack_engine.governance.rbac import Principal, Role, admin, approver
from attack_engine.manager import EngagementManager
from attack_engine.schemas import Scope
from attack_engine.toolrunner.registry import default_registry
from attack_engine.toolrunner.sandbox import NoopSandbox


@pytest.fixture
def engine() -> Engine:
    settings = Settings(env="test", model_mock=True, audit_backend=AuditBackend.MEMORY,
                        eventbus_backend=EventBusBackend.MEMORY, sandbox_backend=SandboxBackend.NOOP)
    audit = AuditLog(MemoryAuditBackend())
    return Engine(settings, audit=audit, event_bus=InMemoryEventBus(),
                  gateway=ModelGateway(settings=settings, provider=MockProvider(), audit=audit),
                  sandbox=NoopSandbox(), registry=default_registry())


@pytest.fixture
def manager(engine: Engine) -> EngagementManager:
    return EngagementManager(engine)


def _scope(eid: str) -> Scope:
    return Scope(engagement_id=eid, allowed_cidrs=("10.5.0.0/24",),
                 authorized_by="t@8pi.ai", signature="sig")


def test_admin_opens_engagement_audited(manager: EngagementManager, engine: Engine) -> None:
    eng = manager.open(_scope("engagement-a"), admin("root@x"))
    assert eng.scope.engagement_id == "engagement-a"
    assert "engagement.open" in [e.action for e in engine.audit.entries("engagement-a")]


def test_non_manager_cannot_open(manager: EngagementManager) -> None:
    op = Principal(id="op@x", roles=frozenset({Role.OPERATOR}), engagements=frozenset({"engagement-a"}))
    with pytest.raises(AuthorizationError, match="manage_engagement"):
        manager.open(_scope("engagement-a"), op)


def test_isolation_principal_cannot_read_other_engagement(manager: EngagementManager) -> None:
    manager.open(_scope("engagement-a"), admin("root@x"))
    manager.open(_scope("engagement-b"), admin("root@x"))
    # A viewer scoped only to engagement-a must not reach engagement-b.
    viewer_a = Principal(id="v@x", roles=frozenset({Role.VIEWER}),
                         engagements=frozenset({"engagement-a"}))
    assert manager.get("engagement-a", viewer_a).scope.engagement_id == "engagement-a"
    with pytest.raises(AuthorizationError, match="no access"):
        manager.get("engagement-b", viewer_a)


def test_list_open_filters_by_access(manager: EngagementManager) -> None:
    manager.open(_scope("engagement-a"), admin("root@x"))
    manager.open(_scope("engagement-b"), admin("root@x"))
    viewer_a = Principal(id="v@x", roles=frozenset({Role.VIEWER}),
                         engagements=frozenset({"engagement-a"}))
    assert manager.list_open(viewer_a) == ["engagement-a"]
    assert set(manager.list_open(admin("root@x"))) == {"engagement-a", "engagement-b"}


def test_get_unopened_engagement_denied(manager: EngagementManager) -> None:
    with pytest.raises(AuthorizationError, match="not open"):
        manager.get("engagement-z", admin("root@x"))


def test_approver_wired_gate_enforces_segregation(manager: EngagementManager, engine: Engine) -> None:
    # Open with an approver principal → exploit-confirm gate honours only them.
    eng = manager.open(_scope("engagement-a"), admin("root@x"),
                       approver=approver("boss@x", "engagement-a"))
    resp = eng.context.gate.require(
        engagement_id="engagement-a", gate="exploit_confirm", requested_by="exploit_confirmer"
    )
    from attack_engine.governance.gates import GateDecision
    assert resp.decision is GateDecision.APPROVED
    assert resp.approver == "boss@x"


def test_close_requires_manage_and_audits(manager: EngagementManager, engine: Engine) -> None:
    manager.open(_scope("engagement-a"), admin("root@x"))
    manager.close("engagement-a", admin("root@x"))
    assert "engagement.close" in [e.action for e in engine.audit.entries("engagement-a")]
    assert manager.list_open(admin("root@x")) == []
