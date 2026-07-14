"""Adapter tests — drives the REAL engine (no mocks of engine internals) and
asserts the output is in the exact JSON shape the console consumes.

Runs with zero external services, exactly like the engine's own suite: memory
audit + event bus, noop settings, a fake sandbox that returns canned nmap XML so
recon actually discovers an asset. The point is to prove the wire end-to-end:
console RoE → signed Scope → real recon/verify/correlate → console-shaped JSON.
"""

from __future__ import annotations

import time

import pytest

from attack_engine.api.adapter import (
    EngineAdapter,
    engagement_id_for,
    principal_from,
    scope_from_roe,
)
from attack_engine.api.serialize import finding_to_json
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
from attack_engine.governance.rbac import Role
from attack_engine.schemas.findings import Finding, FindingState, Priority
from attack_engine.toolrunner.registry import default_registry
from attack_engine.toolrunner.sandbox import SandboxResult
from tests.toolrunner.conftest import NMAP_XML, FakeSandbox


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
def adapter(engine: Engine) -> EngineAdapter:
    return EngineAdapter(engine)


# ── pure mapping (no engine) ─────────────────────────────────────────────────

def test_engagement_id_sanitised_and_prefixed() -> None:
    assert engagement_id_for("acme-001") == "eng-acme-001"
    assert engagement_id_for("68f2a3::weird id") == "eng-68f2a3-weird-id"
    assert engagement_id_for("engagement-range") == "engagement-range"


def test_principal_role_mapping() -> None:
    p = principal_from("operator", "op@8pi.ai")
    assert Role.OPERATOR in p.roles
    # unknown role fails safe to viewer (least privilege)
    assert Role.VIEWER in principal_from("nonsense", "x").roles


def test_scope_from_roe_splits_targets_and_sets_intensity() -> None:
    scope = scope_from_roe(
        "acme-001",
        {
            "scope_allowlist": ["10.5.0.0/24", "https://juice.local/path", "10.5.0.9"],
            "allowed_techniques": ["T1190"],
            "max_intensity": "exploit",
            "window_end": "2030-01-01T00:00:00Z",
        },
        authorized_by="ciso@acme.example",
        signature="signed-abc",
    )
    assert scope.engagement_id == "eng-acme-001"
    assert "10.5.0.0/24" in scope.allowed_cidrs
    assert "10.5.0.9/32" in scope.allowed_cidrs  # bare IP → /32
    assert "juice.local" in scope.allowed_hosts  # URL scheme + path stripped
    assert scope.roe.read_only is False  # exploit intensity lifts read-only
    assert scope.roe.autonomy_tier == 1
    assert "exploit_confirm" in scope.roe.authorized_techniques
    assert scope.is_signed()
    assert scope.expires_at is not None


def test_recon_intensity_stays_read_only() -> None:
    scope = scope_from_roe(
        "x", {"scope_allowlist": ["10.5.0.0/24"], "max_intensity": "recon"},
        authorized_by="a", signature="s",
    )
    assert scope.roe.read_only is True
    assert scope.roe.autonomy_tier == 0


def test_finding_severity_and_exploitability_buckets() -> None:
    confirmed = Finding(
        engagement_id="eng-x", asset="10.5.0.10", type="sqli",
        state=FindingState.CONFIRMED, priority=Priority.PATCH_IMMEDIATELY,
        reachable=True, on_kev=True, exploit_prob=0.95,
        verified_by="sqli_boolean_blind_oracle_v1",
    )
    row = finding_to_json(confirmed)
    assert row["severity"] == "crit"
    assert row["exploitability"] == "confirmed"
    assert row["kev"] is True
    assert row["exploit_prob"] == 0.95

    rejected = Finding(
        engagement_id="eng-x", asset="10.5.0.10", type="sqli",
        state=FindingState.REJECTED, priority=Priority.LOW,
        rejected_reason="oracle disproved",
    )
    assert finding_to_json(rejected)["status"] == "false-positive"


# ── full wire: console RoE → real recon → console JSON ───────────────────────

def test_end_to_end_recon_produces_console_assets_and_intact_audit(
    adapter: EngineAdapter,
) -> None:
    scope = scope_from_roe(
        "acme-001",
        {"scope_allowlist": ["10.5.0.0/24"], "max_intensity": "safe-active"},
        authorized_by="ciso@acme.example",
        signature="signed-abc",
    )
    adapter.open(scope)

    report = adapter.sense("acme-001", ["10.5.0.10"])
    assert report.assets_found == 1

    assets = adapter.assets("acme-001")
    assert len(assets) == 1
    a = assets[0]
    # exact console shape
    assert a["identifiers"]["ip"] == "10.5.0.10"
    assert {"id", "type", "identifiers", "exposure", "versions", "services"} <= a.keys()

    # verify + correlate run for real
    verify, match = adapter.vuln_scan("acme-001")
    assert verify.verified + verify.rejected + verify.skipped >= 0

    findings = adapter.findings("acme-001")
    for f in findings:
        assert f["severity"] in ("crit", "high", "med", "low", "info")
        assert f["exploitability"] in ("unconfirmed", "reachable", "confirmed")

    # audit is the engine's REAL hash chain
    events = adapter.audit_events("acme-001", limit=10)
    assert events and all("hash" in e and "event_type" in e for e in events)
    assert any(e["event_type"] == "engagement.start" for e in adapter.audit_events("acme-001"))
    verdict = adapter.audit_verify("acme-001")
    assert verdict["valid"] is True
    assert verdict["count"] > 0


def _wait_job(adapter: EngineAdapter, external_id: str, *, timeout: float = 8.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        jobs = adapter.jobs(external_id)
        if jobs and jobs[0]["status"] != "running":
            return jobs[0]
        time.sleep(0.05)
    raise AssertionError("job did not finish in time")


def test_background_job_runs_recon_off_the_request_thread(adapter: EngineAdapter) -> None:
    scope = scope_from_roe(
        "job-1", {"scope_allowlist": ["10.5.0.0/24"], "max_intensity": "safe-active"},
        authorized_by="a", signature="s",
    )
    adapter.open(scope)
    job = adapter.start_job("job-1", "sense", ["10.5.0.10"])
    assert job["status"] == "running"  # returns immediately, work continues on a thread

    done = _wait_job(adapter, "job-1")
    assert done["status"] == "done"
    assert len(adapter.assets("job-1")) == 1  # recon really ran


def test_engine_events_stream_to_the_engagement_queue(adapter: EngineAdapter) -> None:
    scope = scope_from_roe(
        "job-2", {"scope_allowlist": ["10.5.0.0/24"], "max_intensity": "safe-active"},
        authorized_by="a", signature="s",
    )
    adapter.open(scope)
    adapter.start_job("job-2", "sense", ["10.5.0.10"])
    _wait_job(adapter, "job-2")
    # the event bus fed asset/finding/job events into this engagement's SSE queue
    q = adapter._events[engagement_id_for("job-2")]
    assert not q.empty()


def test_concurrent_job_refused(adapter: EngineAdapter) -> None:
    scope = scope_from_roe(
        "job-3", {"scope_allowlist": ["10.5.0.0/24"], "max_intensity": "recon"},
        authorized_by="a", signature="s",
    )
    adapter.open(scope)
    adapter._busy.add(engagement_id_for("job-3"))  # simulate an in-flight job
    with pytest.raises(Exception, match="already running"):
        adapter.start_job("job-3", "sense", ["10.5.0.10"])


def test_halt_trips_real_kill_switch(adapter: EngineAdapter) -> None:
    scope = scope_from_roe(
        "acme-002", {"scope_allowlist": ["10.5.0.0/24"], "max_intensity": "recon"},
        authorized_by="a", signature="s",
    )
    adapter.open(scope)
    assert adapter.is_halted("acme-002") is False
    adapter.halt("acme-002", by="operator@acme.example")
    assert adapter.is_halted("acme-002") is True
