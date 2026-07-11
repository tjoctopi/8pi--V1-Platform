"""Tool Runner boundary tests — the enforcement order that gates all offense."""

from __future__ import annotations

import pytest

from attack_engine.errors import (
    RateLimitExceededError,
    RoEViolationError,
    ScopeViolationError,
    ToolNotRegisteredError,
)
from attack_engine.eventbus.memory import InMemoryEventBus
from attack_engine.governance.audit import AuditLog
from attack_engine.schemas import RateLimit, RulesOfEngagement, Scope
from attack_engine.schemas.events import EventType
from attack_engine.schemas.tools import ToolProfile
from attack_engine.toolrunner.registry import default_registry
from attack_engine.toolrunner.runner import ToolRunner

from .conftest import FakeSandbox


@pytest.fixture
def audit() -> AuditLog:
    return AuditLog()


@pytest.fixture
def bus() -> InMemoryEventBus:
    return InMemoryEventBus()


@pytest.fixture
def runner(scope: Scope, audit: AuditLog, bus: InMemoryEventBus, fake_sandbox: FakeSandbox) -> ToolRunner:
    return ToolRunner(
        scope,
        registry=default_registry(),
        audit=audit,
        sandbox=fake_sandbox,
        event_bus=bus,
    )


class TestHappyPath:
    def test_nmap_run_produces_parsed_result(self, runner: ToolRunner) -> None:
        result = runner.run("nmap", "10.0.4.12")
        assert result.ok
        assert result.tool == "nmap"
        assert result.audit_id
        ports = {p["port"] for p in result.parsed["ports"]}
        assert ports == {80, 3306}

    def test_run_is_audited_with_raw(self, runner: ToolRunner, audit: AuditLog) -> None:
        result = runner.run("nmap", "10.0.4.12")
        entry = next(e for e in audit.entries() if e.action == "tool.run")
        assert entry.entry_hash == result.audit_id
        assert entry.raw_sha256 is not None
        # Full-fidelity raw output is retrievable from the audit log.
        assert audit.get_raw(entry) is not None
        assert audit.verify() is True

    def test_run_emits_started_and_completed(self, runner: ToolRunner, bus: InMemoryEventBus) -> None:
        events: list = []
        bus.subscribe(events.append)
        runner.run("nmap", "10.0.4.12")
        types = [e.event for e in events]
        assert EventType.TOOL_STARTED in types
        assert EventType.TOOL_COMPLETED in types

    def test_argv_reaches_sandbox(self, runner: ToolRunner, fake_sandbox: FakeSandbox) -> None:
        runner.run("nmap", "10.0.4.12", ToolProfile(preset="quick"))
        assert fake_sandbox.calls[0].argv[0] == "nmap"
        assert "10.0.4.12" in fake_sandbox.calls[0].argv

    def test_call_count_increments_only_on_execution(self, runner: ToolRunner) -> None:
        runner.run("nmap", "10.0.4.12")
        runner.run("ffuf", "10.0.4.12")
        assert runner.call_count == 2


class TestScopeRefusal:
    def test_out_of_scope_target_refused_before_execution(
        self, runner: ToolRunner, fake_sandbox: FakeSandbox
    ) -> None:
        with pytest.raises(ScopeViolationError):
            runner.run("nmap", "8.8.8.8")
        # The sandbox was never invoked.
        assert fake_sandbox.calls == []

    def test_refusal_is_audited_and_emitted(
        self, runner: ToolRunner, audit: AuditLog, bus: InMemoryEventBus
    ) -> None:
        events: list = []
        bus.subscribe(events.append)
        with pytest.raises(ScopeViolationError):
            runner.run("nmap", "8.8.8.8")
        actions = [e.action for e in audit.entries()]
        assert "tool.refused" in actions
        assert EventType.TOOL_REFUSED in [e.event for e in events]
        assert audit.verify() is True


class TestRoERefusal:
    def test_forbidden_tool_refused(self, scope: Scope, audit: AuditLog, fake_sandbox: FakeSandbox) -> None:
        forbidden_scope = scope.model_copy(
            update={"roe": RulesOfEngagement(forbidden_tools=frozenset({"nmap"}))}
        )
        runner = ToolRunner(
            forbidden_scope, registry=default_registry(), audit=audit, sandbox=fake_sandbox
        )
        with pytest.raises(RoEViolationError, match="denylist"):
            runner.run("nmap", "10.0.4.12")
        assert fake_sandbox.calls == []

    def test_mutating_profile_refused_under_read_only(
        self, scope: Scope, audit: AuditLog, fake_sandbox: FakeSandbox
    ) -> None:
        # Register a wrapper that declares itself mutating for this profile.
        from attack_engine.toolrunner.registry import ToolRegistry
        from attack_engine.toolrunner.wrappers.base import ToolWrapper

        class MutatorWrapper(ToolWrapper):
            name = "mutator"
            default_image = "x"

            def build_argv(self, target, profile):
                return ["mutator", target]

            def parse(self, target, result):
                return {}

            def is_mutating(self, profile):
                return True

        reg = ToolRegistry()
        reg.register(MutatorWrapper())
        runner = ToolRunner(scope, registry=reg, audit=audit, sandbox=fake_sandbox)
        with pytest.raises(RoEViolationError, match="read-only"):
            runner.run("mutator", "10.0.4.12")
        assert fake_sandbox.calls == []

    def test_call_budget_exhaustion(self, scope: Scope, audit: AuditLog, fake_sandbox: FakeSandbox) -> None:
        budgeted = scope.model_copy(
            update={"roe": RulesOfEngagement(max_total_tool_calls=1)}
        )
        runner = ToolRunner(
            budgeted, registry=default_registry(), audit=audit, sandbox=fake_sandbox
        )
        runner.run("nmap", "10.0.4.12")
        with pytest.raises(RoEViolationError, match="budget"):
            runner.run("nmap", "10.0.4.13")


class TestRateLimitRefusal:
    def test_rate_limit_refuses_and_audits(self, audit: AuditLog, fake_sandbox: FakeSandbox) -> None:
        scope = Scope(
            engagement_id="eng-rl",
            allowed_cidrs=("10.0.4.0/24",),
            roe=RulesOfEngagement(default_rate_limit=RateLimit(requests_per_sec=1, burst=1)),
        )
        runner = ToolRunner(scope, registry=default_registry(), audit=audit, sandbox=fake_sandbox)
        runner.run("nmap", "10.0.4.12")
        with pytest.raises(RateLimitExceededError):
            runner.run("nmap", "10.0.4.12")
        assert "tool.refused" in [e.action for e in audit.entries()]


class TestRegistryErrors:
    def test_unknown_tool_raises(self, runner: ToolRunner) -> None:
        with pytest.raises(ToolNotRegisteredError):
            runner.run("metasploit", "10.0.4.12")
