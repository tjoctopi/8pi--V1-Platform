"""Sprint 3 exit-gate acceptance test.

    "A real scoped engagement produces a reachability-prioritised risk map +
     hardening actions a partner would pay for."

Run under RBAC (an admin opens the engagement; a segregated approver authorises
the gate) through the EngagementManager, then score the result against the
ground-truth range with the eval harness. Everything audited; tenants isolated.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from attack_engine.config import (
    AuditBackend,
    EventBusBackend,
    SandboxBackend,
    Settings,
)
from attack_engine.correlate.nvd import build_feed
from attack_engine.engine import Engine
from attack_engine.evals.dataset import GroundTruth
from attack_engine.evals.runner import EvalRunner
from attack_engine.evals.tracking import LocalJsonTracker
from attack_engine.eventbus.memory import InMemoryEventBus
from attack_engine.gateway.provider import MockProvider
from attack_engine.gateway.router import ModelGateway
from attack_engine.governance.audit import AuditLog
from attack_engine.governance.audit_backends import MemoryAuditBackend
from attack_engine.governance.rbac import AccessControl, Principal, Role, admin, approver
from attack_engine.manager import EngagementManager
from attack_engine.schemas import RateLimit, RulesOfEngagement, Scope
from attack_engine.schemas.findings import FindingState, Priority
from attack_engine.toolrunner.registry import default_registry
from attack_engine.toolrunner.sandbox import Sandbox, SandboxResult, SandboxSpec
from tests.toolrunner.conftest import NMAP_XML

LABELS = Path(__file__).resolve().parents[1] / "src/attack_engine/evals/data/range_labels.json"

# NVD + KEV docs matching the range ground truth (Apache 2.4.49 on KEV).
NVD_DOC = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-41773",
                "descriptions": [{"lang": "en", "value": "Apache 2.4.49 path traversal."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-22"}]}],
                "configurations": [{"nodes": [{"cpeMatch": [
                    {"vulnerable": True,
                     "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                     "versionStartIncluding": "2.4.49", "versionEndExcluding": "2.4.50"}
                ]}]}],
            }
        }
    ]
}
KEV_DOC = {"vulnerabilities": [{"cveID": "CVE-2021-41773"}]}

NUCLEI_SQLI = (
    b'{"template-id":"sqli-detection","info":{"name":"SQL Injection","severity":"high"},'
    b'"matched-at":"http://10.5.0.10:3000/rest/products/search?q=apples","type":"http"}\n'
)
SQLMAP_INJECTABLE = b"Parameter: q (GET)\n    Type: boolean-based blind\n"


class RangeSandbox(Sandbox):
    name = "range"

    def __init__(self) -> None:
        self.calls: list[SandboxSpec] = []

    def run(self, spec: SandboxSpec) -> SandboxResult:
        self.calls.append(spec)
        b = spec.argv[0] if spec.argv else ""
        if b == "nmap":
            return SandboxResult(0, NMAP_XML, b"", 0.05, self.name)
        if b == "nuclei":
            return SandboxResult(0, NUCLEI_SQLI, b"", 0.1, self.name)
        if b == "sqlmap":
            return SandboxResult(0, SQLMAP_INJECTABLE, b"", 0.2, self.name)
        if b == "curl":
            url = spec.argv[-1]
            injectable = "/rest/products/search" in url
            size = 5120 if (injectable and "%3D%271" in url) else 128
            return SandboxResult(0, f"HTTP:200 SIZE:{size} TIME:0.01".encode(), b"", 0.01, self.name)
        return SandboxResult(0, b"", b"", 0.01, self.name)


@pytest.fixture
def engine() -> Engine:
    settings = Settings(env="test", model_mock=True, audit_backend=AuditBackend.MEMORY,
                        eventbus_backend=EventBusBackend.MEMORY, sandbox_backend=SandboxBackend.NOOP)
    audit = AuditLog(MemoryAuditBackend())
    return Engine(
        settings, audit=audit, event_bus=InMemoryEventBus(),
        gateway=ModelGateway(settings=settings, provider=MockProvider(), audit=audit),
        sandbox=RangeSandbox(), registry=default_registry(),
        feed=build_feed(NVD_DOC, KEV_DOC),  # the real NVD/KEV ingest path
    )


@pytest.fixture
def scope() -> Scope:
    return Scope(engagement_id="engagement-partner", allowed_cidrs=("10.5.0.0/24",),
                 roe=RulesOfEngagement(default_rate_limit=RateLimit(requests_per_sec=1000, burst=1000)),
                 authorized_by="ciso@partner.example", signature="signed")


def test_sprint3_exit_gate(engine: Engine, scope: Scope, tmp_path: Path) -> None:
    # --- RBAC: an admin opens the engagement; a segregated approver holds gates ---
    manager = EngagementManager(engine, access=AccessControl())
    boss = approver("ciso@partner.example", "engagement-partner")
    engagement = manager.open(scope, admin("root@8pi.ai"), approver=boss)

    # A viewer scoped elsewhere cannot reach this tenant (isolation).
    from attack_engine.errors import AuthorizationError
    outsider = Principal(id="x@other", roles=frozenset({Role.VIEWER}),
                         engagements=frozenset({"some-other-engagement"}))
    with pytest.raises(AuthorizationError):
        manager.get("engagement-partner", outsider)

    # --- Run the full loop (built from the real NVD/KEV feed) ---
    blue = engine.blue_sentry(scope)
    result = engagement.orchestrator(blue_sentry=blue).run(["10.5.0.10"], goal="partner-assessment")
    report = result.report

    # --- A reachability-prioritised risk map a partner would pay for ---
    assert report.risk_map
    top = report.risk_map[0]
    assert top.reachable and top.risk > 0.0  # the top risk is actually reachable
    assert any(e.type == "CVE-2021-41773" and e.on_kev for e in report.risk_map)
    # --- with concrete hardening actions ---
    assert report.hardening_actions
    assert any("Upgrade" in a for a in report.hardening_actions)

    # --- Prove accuracy against the ground-truth range (eval harness) ---
    gt = GroundTruth.from_json(LABELS)
    tracker = LocalJsonTracker(tmp_path / "evals.jsonl")
    eval_report = EvalRunner(gt, tracker=tracker).evaluate(
        engagement.store.findings(), name="partner-assessment", model_id="fireworks-oss"
    )
    # Caught both planted vulns, no false positive on the internal-only trap.
    assert eval_report.recall == 1.0
    assert eval_report.precision == 1.0
    assert eval_report.fp == 0
    assert tracker.runs()  # the eval run was recorded

    # --- Everything audited, chain intact, RBAC-open recorded ---
    actions = [e.action for e in engine.audit.entries("engagement-partner")]
    assert "engagement.open" in actions
    assert "finding.correlate" in actions
    assert engine.audit.verify() is True

    # --- The KEV-flagged, reachable Apache CVE is patch-immediately ---
    confirmed = engagement.store.findings(FindingState.CONFIRMED)
    apache = next(f for f in confirmed if f.type == "CVE-2021-41773")
    assert apache.priority is Priority.PATCH_IMMEDIATELY and apache.on_kev
