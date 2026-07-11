"""Sprint 1 exit-gate acceptance test.

    "Engine confirms a planted SQLi in the range, scores it calibrated, and
     stops at the gate instead of exploiting; correlator flags a known-vulnerable
     Apache as 'patch immediately' while ignoring an internal-only theoretical
     CVE."

Driven end-to-end through the Engine with scripted tool output. The human gate
is wired to auto-approve so the confirm-only step runs; the point is that it
*went through the gate* (audited) and never extracted data.
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
from attack_engine.schemas.findings import Asset, Finding, FindingState, Priority, Service
from attack_engine.toolrunner.registry import default_registry
from attack_engine.toolrunner.sandbox import Sandbox, SandboxResult, SandboxSpec
from tests.toolrunner.conftest import NMAP_XML

NUCLEI_SQLI = (
    b'{"template-id":"sqli-detection","info":{"name":"SQL Injection","severity":"high"},'
    b'"matched-at":"http://10.5.0.10:3000/rest/products/search?q=apples","type":"http"}\n'
)
SQLMAP_INJECTABLE = b"Parameter: q (GET)\n    Type: boolean-based blind\n"


class RangeSandbox(Sandbox):
    """Scripts every tool the Sprint 1 loop touches on the range."""

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
            # Only the real injection point is vulnerable; the active screen must
            # not "confirm" injections at endpoints that don't have one.
            injectable = "/rest/products/search" in url
            true_cond = "%3D%271" in url  # ...='1  (TRUE payload)
            size = 5120 if (injectable and true_cond) else 128
            return SandboxResult(0, f"HTTP:200 SIZE:{size} TIME:0.01".encode(), b"", 0.01, self.name)
        return SandboxResult(0, b"", b"", 0.01, self.name)


@pytest.fixture
def engine() -> Engine:
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
        sandbox=RangeSandbox(),
        registry=default_registry(),
        gate_responder=approve_all("security-lead"),  # human approves the confirm
    )


@pytest.fixture
def scope() -> Scope:
    return Scope(
        engagement_id="engagement-range",
        allowed_cidrs=("10.5.0.0/24",),
        roe=RulesOfEngagement(
            default_rate_limit=RateLimit(requests_per_sec=1000, burst=1000)
        ),
        authorized_by="tester@8pi.ai", signature="sig",
    )


def test_sprint1_exit_gate(engine: Engine, scope: Scope) -> None:
    eng = engine.engagement(scope)
    store = eng.store

    # --- Set up the range state the recon stage would have produced ---
    # Reachable internet-facing web host running the vulnerable Apache 2.4.49.
    store.add_asset(Asset(address="10.5.0.10", engagement_id="engagement-range",
                          services=(Service(port=80, product="Apache httpd", version="2.4.49"),
                                    Service(port=3000, name="http"))))
    # Internal-only DB host (NOT reachable from entry) running MySQL 5.5.61.
    store.add_asset(Asset(address="10.5.0.99", engagement_id="engagement-range",
                          services=(Service(port=3306, product="MySQL", version="5.5.61"),)),
                    reachable_from_entry=False)
    # Propose the service observations (as the Surface Mapper would).
    store.propose_finding(Finding(engagement_id="engagement-range", asset="10.5.0.10",
                                  type="exposed-service:80/tcp", service="Apache httpd/2.4.49",
                                  metadata={"port": 80}))
    store.propose_finding(Finding(engagement_id="engagement-range", asset="10.5.0.99",
                                  type="exposed-service:3306/tcp", service="MySQL/5.5.61",
                                  metadata={"port": 3306}))

    # --- Web Inquisitor: surfaces the SQLi candidate on the web host ---
    from pathlib import Path

    from attack_engine.agents.loader import load_spec
    specs = Path(__file__).resolve().parents[1] / "src/attack_engine/agents/specs"
    eng.run_agent(load_spec(specs / "web_inquisitor.yaml"), ["http://10.5.0.10:3000"])
    assert any(f.type == "sqli-candidate" for f in store.findings())

    # --- Exploit-Confirmer: stops at the human gate, then confirms (no extraction) ---
    eng.run_agent(load_spec(specs / "exploit_confirmer.yaml"), ["10.5.0.10"])
    gate_actions = [e.action for e in engine.audit.entries()]
    assert "gate.request" in gate_actions and "gate.approved" in gate_actions
    # SQLMap ran in confirm-only mode — no extraction flag ever emitted.
    sqlmap_calls = [c for c in engine.sandbox.calls if c.argv[0] == "sqlmap"]  # type: ignore[attr-defined]
    assert sqlmap_calls
    assert all("--technique=B" in c.argv for c in sqlmap_calls)
    assert not any(a.startswith("--dump") or a in {"--dbs", "--tables"}
                   for c in sqlmap_calls for a in c.argv)

    # --- Verifier: the independent oracle confirms the planted SQLi + scores it ---
    eng.verify()
    sqli = [f for f in store.findings() if f.type == "sqli-boolean-blind"]
    assert sqli, "SQLi finding should exist"
    assert sqli[0].state is FindingState.VERIFIED  # oracle passed
    assert sqli[0].exploit_prob is not None and sqli[0].exploit_prob > 0.0  # scored (calibrated)

    # --- Exploitability Matcher: correlate services to CVEs ---
    report = eng.correlate()
    confirmed = store.findings(FindingState.CONFIRMED)

    # Apache 2.4.49 (reachable, on KEV) → patch immediately.
    apache = [f for f in confirmed if f.type.startswith("CVE-2021-417")]
    assert apache
    assert any(f.priority is Priority.PATCH_IMMEDIATELY and f.on_kev for f in apache)
    assert report.patch_immediately >= 1

    # Internal-only MySQL theoretical CVE → recorded but deprioritised.
    mysql = [f for f in confirmed if f.type == "CVE-2012-2122"]
    assert mysql and mysql[0].priority is Priority.INFORMATIONAL

    # --- Governance: the whole run is audited and the chain is intact ---
    assert engine.audit.verify() is True
    actions = [e.action for e in engine.audit.entries()]
    assert "finding.verify" in actions
    assert "finding.correlate" in actions
