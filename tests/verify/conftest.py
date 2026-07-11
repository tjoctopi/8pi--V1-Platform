"""Fixtures for verification tests: a payload-aware fake sandbox + a VerifyContext."""

from __future__ import annotations

import pytest

from attack_engine.governance.audit import AuditLog
from attack_engine.knowledge.store import KnowledgeStore
from attack_engine.schemas import RateLimit, RulesOfEngagement, Scope
from attack_engine.toolrunner.registry import default_registry
from attack_engine.toolrunner.runner import ToolRunner
from attack_engine.toolrunner.sandbox import Sandbox, SandboxResult, SandboxSpec
from attack_engine.verify.context import VerifyContext
from tests.toolrunner.conftest import NMAP_XML


class SqliRangeSandbox(Sandbox):
    """Simulates a boolean-blind-SQLi-vulnerable endpoint.

    For ``curl`` (http_probe): a TRUE-condition payload (``'1'='1``) yields a
    "full results" page (large SIZE); a FALSE-condition payload (``'1'='2``)
    yields an "empty results" page (small SIZE). A *non-vulnerable* param would
    return the same size regardless — configurable via ``vulnerable``.
    For ``nmap``: returns the standard fixture so version re-grab is stable.
    """

    name = "fake-sqli"

    def __init__(self, vulnerable: bool = True) -> None:
        self.vulnerable = vulnerable
        self.calls: list[SandboxSpec] = []

    def run(self, spec: SandboxSpec) -> SandboxResult:
        self.calls.append(spec)
        binary = spec.argv[0] if spec.argv else ""
        if binary == "nmap":
            return SandboxResult(0, NMAP_XML, b"", 0.05, self.name)
        if binary == "curl":
            url = spec.argv[-1]
            true_condition = "1'%3D'1" in url or "1'='1" in url or "%271%27%3D%271" in url
            if self.vulnerable and true_condition:
                size = 5120  # full result set
            else:
                size = 128  # empty / error page
            body = f"HTTP:200 SIZE:{size} TIME:0.012".encode()
            return SandboxResult(0, body, b"", 0.012, self.name)
        return SandboxResult(0, b"", b"", 0.01, self.name)


@pytest.fixture
def scope() -> Scope:
    return Scope(
        engagement_id="engagement-range",
        allowed_cidrs=("10.5.0.0/24",),
        roe=RulesOfEngagement(
            default_rate_limit=RateLimit(requests_per_sec=1000, burst=100)
        ),
        authorized_by="tester@8pi.ai",
        signature="sig",
    )


@pytest.fixture
def audit() -> AuditLog:
    return AuditLog()


def make_verify_ctx(scope: Scope, audit: AuditLog, sandbox: Sandbox) -> VerifyContext:
    store = KnowledgeStore(scope.engagement_id)
    runner = ToolRunner(
        scope, registry=default_registry(), audit=audit, sandbox=sandbox, actor="verifier"
    )
    return VerifyContext(
        engagement_id=scope.engagement_id, tool_runner=runner, store=store, audit=audit
    )
