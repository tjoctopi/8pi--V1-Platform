"""Licensed-scanner gating tests — refused until procurement sign-off in RoE."""

from __future__ import annotations

import pytest

from attack_engine.errors import RoEViolationError
from attack_engine.governance.audit import AuditLog
from attack_engine.schemas import RateLimit, RulesOfEngagement, Scope
from attack_engine.schemas.tools import ToolProfile
from attack_engine.toolrunner.registry import default_registry
from attack_engine.toolrunner.runner import ToolRunner
from attack_engine.toolrunner.sandbox import SandboxResult
from attack_engine.toolrunner.wrappers.licensed import BurpEnterpriseWrapper, NessusWrapper

from .conftest import FakeSandbox


def _scope(*, licensed: frozenset[str] = frozenset()) -> Scope:
    return Scope(
        engagement_id="eng-lic",
        allowed_cidrs=("10.5.0.0/24",),
        roe=RulesOfEngagement(
            default_rate_limit=RateLimit(requests_per_sec=1000, burst=50),
            licensed_tools_enabled=licensed,
        ),
        authorized_by="t@8pi.ai", signature="sig",
    )


def _runner(scope: Scope, sandbox: FakeSandbox) -> ToolRunner:
    return ToolRunner(scope, registry=default_registry(), audit=AuditLog(), sandbox=sandbox)


class TestGating:
    def test_nessus_refused_by_default(self) -> None:
        sandbox = FakeSandbox()
        runner = _runner(_scope(), sandbox)
        with pytest.raises(RoEViolationError, match="licensed tool not enabled"):
            runner.run("nessus", "10.5.0.10")
        assert sandbox.calls == []  # never executed

    def test_burp_refused_by_default(self) -> None:
        sandbox = FakeSandbox()
        runner = _runner(_scope(), sandbox)
        with pytest.raises(RoEViolationError, match="licensed"):
            runner.run("burp_enterprise", "10.5.0.10")

    def test_refusal_is_audited(self) -> None:
        sandbox = FakeSandbox()
        audit = AuditLog()
        runner = ToolRunner(_scope(), registry=default_registry(), audit=audit, sandbox=sandbox)
        with pytest.raises(RoEViolationError):
            runner.run("nessus", "10.5.0.10")
        refusals = [e for e in audit.entries() if e.action == "tool.refused"]
        assert refusals and refusals[0].payload["reason"] == "licensed_not_enabled"

    def test_nessus_allowed_when_procurement_signed_off(self) -> None:
        sandbox = FakeSandbox()
        sandbox.set_response(
            "nessus-scan",
            SandboxResult(
                0,
                b'{"vulnerabilities":[{"plugin_id":1,"plugin_name":"x","severity":3,"cve":["CVE-1"]}]}',
                b"", 0.1, "fake"),
        )
        runner = _runner(_scope(licensed=frozenset({"nessus"})), sandbox)
        result = runner.run("nessus", "10.5.0.10")
        assert result.ok
        assert result.parsed["findings"][0]["cve"] == ["CVE-1"]

    def test_only_the_enabled_tool_is_allowed(self) -> None:
        # Enabling nessus must NOT implicitly enable burp.
        runner = _runner(_scope(licensed=frozenset({"nessus"})), FakeSandbox())
        with pytest.raises(RoEViolationError):
            runner.run("burp_enterprise", "10.5.0.10")


class TestWrappers:
    def test_nessus_marked_licensed(self) -> None:
        assert NessusWrapper().licensed is True
        assert BurpEnterpriseWrapper().licensed is True

    def test_burp_builds_url(self) -> None:
        argv = BurpEnterpriseWrapper().build_argv("10.5.0.10", ToolProfile(args={"scheme": "https"}))
        assert "https://10.5.0.10" in argv
