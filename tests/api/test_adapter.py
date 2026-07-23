"""Adapter tests — drives the REAL engine (no mocks of engine internals) and
asserts the output is in the exact JSON shape the console consumes.

Runs with zero external services, exactly like the engine's own suite: memory
audit + event bus, noop settings, a fake sandbox that returns canned nmap XML so
recon actually discovers an asset. The point is to prove the wire end-to-end:
console RoE → signed Scope → real recon/verify/correlate → console-shaped JSON.
"""

from __future__ import annotations

import time
from typing import Any

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
from attack_engine.errors import AttackEngineError
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


def _adapter_with_test_auth(allow: bool) -> EngineAdapter:
    settings = Settings(
        env="test", model_mock=True, allow_test_authorization=allow,
        audit_backend=AuditBackend.MEMORY, eventbus_backend=EventBusBackend.MEMORY,
        sandbox_backend=SandboxBackend.NOOP,
    )
    audit = AuditLog(MemoryAuditBackend())
    engine = Engine(
        settings, audit=audit, event_bus=InMemoryEventBus(),
        gateway=ModelGateway(settings=settings, provider=MockProvider(), audit=audit),
        sandbox=FakeSandbox(), registry=default_registry(),
    )
    return EngineAdapter(engine)


def test_open_for_testing_one_click_when_enabled() -> None:
    adapter = _adapter_with_test_auth(True)
    eng = adapter.open_for_testing("acme-001", ["10.5.0.12", "https://juice.local"])
    assert eng.scope.is_test_authorization
    assert eng.scope.engagement_id == "eng-acme-001"
    assert "10.5.0.12/32" in eng.scope.allowed_cidrs
    assert "juice.local" in eng.scope.allowed_hosts
    assert adapter.is_open("acme-001")


def test_open_for_testing_refused_without_optin() -> None:
    from attack_engine.errors import AttackEngineError

    adapter = _adapter_with_test_auth(False)
    with pytest.raises(AttackEngineError, match="not enabled"):
        adapter.open_for_testing("acme-001", ["10.5.0.12"])


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


def test_correlated_finding_lands_in_vuln_loop_lane() -> None:
    # A matcher-confirmed vuln (carries correlation output) → console vuln-loop.
    cve = Finding(
        engagement_id="eng-x", asset="10.5.0.10", type="CVE-2021-41773",
        state=FindingState.CONFIRMED, verified_by="interval_match_oracle_v1",
        proposed_by="exploitability_matcher",
        metadata={"cvss": 9.8, "reachability_reason": "reachable from entry"},
    )
    assert finding_to_json(cve)["source"] == "vuln-loop"

    proven_vuln = Finding(
        engagement_id="eng-x", asset="10.5.0.12", type="command-injection",
        state=FindingState.CONFIRMED, verified_by="cmdi_exec_oracle_v1",
        proposed_by="web-inquisitor",
        metadata={"cvss": 9.8, "remediation": "no shell",
                  "reachability_reason": "proven by live probe"},
    )
    # Emitter was the web agent, but the correlation output puts it in the loop.
    assert finding_to_json(proven_vuln)["source"] == "vuln-loop"


def test_uncorrelated_finding_keeps_its_emitter() -> None:
    # A recon/port finding with no correlation output keeps its raw emitter.
    port = Finding(
        engagement_id="eng-x", asset="10.5.0.10", type="exposed-service:80/tcp",
        proposed_by="surface-mapper",
    )
    assert finding_to_json(port)["source"] == "surface-mapper"


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


def _open_signed(adapter: EngineAdapter, external_id: str) -> None:
    scope = scope_from_roe(
        external_id, {"scope_allowlist": ["10.5.0.0/24"], "max_intensity": "safe-active"},
        authorized_by="a", signature="s",
    )
    adapter.open(scope)


def test_world_model_registered_and_view_has_shape(adapter: EngineAdapter) -> None:
    # Every engagement registers one WorldModel bound to its blackboard store.
    _open_signed(adapter, "wm-1")
    eng = adapter.engagement("wm-1")
    assert eng.world_model is not None
    assert eng.world_model.store is eng.store  # shared belief state, one instance
    view = adapter.world_model_view("wm-1")
    assert {"hypotheses", "chains", "owned_principals", "domain_admin_paths",
            "reachable_assets", "counts"} <= view.keys()
    assert {"hypotheses", "graduated", "chains", "chains_realised",
            "owned_principals", "da_paths"} <= view["counts"].keys()


def test_world_model_view_empty_when_closed(adapter: EngineAdapter) -> None:
    view = adapter.world_model_view("never-opened")
    assert view["counts"]["hypotheses"] == 0
    assert view["hypotheses"] == []


def test_run_agent_dispatch_and_guards(adapter: EngineAdapter) -> None:
    _open_signed(adapter, "ra-1")
    # exploit-confirmer runs verify+correlate synchronously and records a run
    out = adapter.run_agent("ra-1", "exploit-confirmer")
    assert out["ok"] is True
    assert any(r["agent_name"] == "Exploit Confirmer" for r in adapter.agent_runs("ra-1"))
    # converter is per-finding — refuses an engagement-wide run with guidance
    with pytest.raises(AttackEngineError):
        adapter.run_agent("ra-1", "converter")
    # unknown archetype fails cleanly
    with pytest.raises(AttackEngineError):
        adapter.run_agent("ra-1", "nope")


def test_run_agent_job_kind_dispatches(adapter: EngineAdapter) -> None:
    _open_signed(adapter, "ra-2")
    job = adapter.start_job("ra-2", "agent-run", agent_id="surface-mapper")
    assert job["kind"] == "agent-run" and job["agent_id"] == "surface-mapper"
    done = _wait_job(adapter, "ra-2")
    assert done["status"] == "done"
    assert len(adapter.assets("ra-2")) == 1  # recon really ran off the request thread


def test_deterministic_web_sweep_graduates_from_crawl(
    adapter: EngineAdapter, engine: Engine
) -> None:
    # Feed the fake sandbox a katana crawl with parameterised endpoints; the sweep
    # must fold them into candidates and graduate the oracle-ready ones — reliably,
    # with no model in the loop (the fix for "runs but finds nothing").
    engine.sandbox.set_response(  # type: ignore[attr-defined]
        "katana",
        SandboxResult(
            0,
            b'{"endpoint":"http://10.5.0.10:80/app.php?id=1&file=x&q=z"}\n',
            b"", 0.05, "fake",
        ),
    )
    _open_signed(adapter, "sweep-1")
    n = adapter._deterministic_web_sweep("sweep-1", ["http://10.5.0.10:80"])
    assert n >= 1  # at least one oracle-ready candidate (sqli/lfi) graduated
    findings = adapter.findings("sweep-1")
    assert findings  # PROPOSED findings exist for verify() to confirm


def test_authorization_view_classifies_techniques_tools_actions(adapter: EngineAdapter) -> None:
    _open_signed(adapter, "authz-1")
    view = adapter.authorization_view("authz-1")
    assert {"live", "tier", "read_only", "signed", "techniques", "tools", "actions",
            "counts"} <= view.keys()
    assert view["techniques"] and view["tools"]
    # every technique carries a real status from the engine's policy
    assert all(t["status"] in ("autonomous", "gated", "gated-evasion")
               for t in view["techniques"])
    # defense-evasion TTPs are always gated-evasion, never autonomous
    evasion = [t for t in view["techniques"] if t["evasion"]]
    assert all(t["status"] == "gated-evasion" for t in evasion) if evasion else True
    # high-impact actions are shown always-gated
    assert all(a["status"] == "gated" for a in view["actions"])


def test_execute_chain_unknown_raises(adapter: EngineAdapter) -> None:
    _open_signed(adapter, "chain-x")
    with pytest.raises(AttackEngineError):
        adapter.execute_chain("chain-x", "chain-does-not-exist")


def test_vuln_scan_auto_recons_when_no_web_surface(adapter: EngineAdapter) -> None:
    # Deployed regression: running Vuln Scan without a prior Sense must still work —
    # the sweep auto-runs recon on the authorized targets so there's a surface to
    # crawl, instead of silently finding nothing.
    _open_signed(adapter, "selfsuff-1")
    assert adapter.assets("selfsuff-1") == []  # no recon yet
    adapter.vuln_scan("selfsuff-1")
    assert len(adapter.assets("selfsuff-1")) >= 1  # vuln_scan auto-ran recon


def test_foothold_candidates_and_establish_guards(adapter: EngineAdapter) -> None:
    from attack_engine.schemas.findings import Finding, FindingState

    _open_signed(adapter, "c2-1")
    eng = adapter.engagement("c2-1")
    # a CONFIRMED command-injection finding with a usable injection point
    f = Finding(
        engagement_id=eng.scope.engagement_id, asset="10.5.0.10",
        type="command-injection", title="cmdi at /dns?target_host",
        metadata={"param": "target_host", "path": "/dns", "scheme": "http",
                  "port": 80, "method": "POST"},
    )
    eng.store.propose_finding(f)
    eng.store.promote_finding(f.id, FindingState.VERIFIED, verified_by="test")
    eng.store.promote_finding(f.id, FindingState.CONFIRMED, verified_by="test")

    cands = adapter.foothold_candidates("c2-1")
    assert any(c["finding_id"] == f.id and c["param"] == "target_host" for c in cands)

    # a PROPOSED (unconfirmed) finding is NOT a foothold candidate and refuses establish
    g = Finding(engagement_id=eng.scope.engagement_id, asset="10.5.0.10",
                type="sqli-boolean-blind", title="maybe", metadata={"param": "id"})
    eng.store.propose_finding(g)
    assert all(c["finding_id"] != g.id for c in adapter.foothold_candidates("c2-1"))
    with pytest.raises(AttackEngineError):
        adapter.establish_foothold("c2-1", g.id)
    with pytest.raises(AttackEngineError):
        adapter.establish_foothold("c2-1", "no-such-finding")

    # post-ex / teardown on a non-existent session refuse cleanly (never crash)
    with pytest.raises(AttackEngineError):
        adapter.session_command("c2-1", "no-session", "id")
    with pytest.raises(AttackEngineError):
        adapter.teardown_session("c2-1", "no-session")
    # sessions view is a valid, empty-safe shape
    view = adapter.sessions("c2-1")
    assert view["sessions"] == [] and any(
        c["finding_id"] == f.id for c in view["candidates"])


def _poi_adapter_with_served_page(body: bytes) -> EngineAdapter:
    """Test-auth adapter whose curl (http_probe) serves ``body`` as the site."""

    settings = Settings(
        env="test", model_mock=True, allow_test_authorization=True,
        audit_backend=AuditBackend.MEMORY, eventbus_backend=EventBusBackend.MEMORY,
        sandbox_backend=SandboxBackend.NOOP,
    )
    sb = FakeSandbox()
    # http_probe drives curl; body then the write-out sentinel line the wrapper parses.
    sb.set_response("curl", SandboxResult(
        0, body + b"\n__AEPROBE__HTTP:200 SIZE:%d TIME:0.02" % len(body),
        b"", 0.02, "fake"))
    audit = AuditLog(MemoryAuditBackend())
    engine = Engine(
        settings, audit=audit, event_bus=InMemoryEventBus(),
        gateway=ModelGateway(settings=settings, provider=MockProvider(), audit=audit),
        sandbox=sb, registry=default_registry(),
    )
    return EngineAdapter(engine)


class _StubPostEx:
    """Minimal post-ex operator: echoes each command as its output."""

    def run(self, session: Any, command: str) -> Any:
        from attack_engine.c2.postex import PostExResult

        return PostExResult(action="run", session_id=session.id, host=session.host,
                            command=command, output=f"out:{command}")


def _seed_foothold(adapter: EngineAdapter, external_id: str) -> tuple[str, Any]:
    eng = adapter.engagement(external_id)
    eid = engagement_id_for(external_id)
    sess = eng.session_manager.open_session("10.5.0.12", opened_by="test")
    finding = Finding(engagement_id=eng.scope.engagement_id, asset="10.5.0.12",
                      type="command-injection", metadata={"param": "host"})
    adapter._footholds.setdefault(eid, {})[sess.id] = {
        "postex": _StubPostEx(), "host": "10.5.0.12", "proof": {"whoami": "www-data"},
        "technique": "T1190", "finding_id": finding.id, "opened_at": "now",
    }
    return sess.id, finding


def test_proof_of_impact_captures_loot_and_site_content() -> None:
    # A fresh foothold auto-runs the bounded loot set AND captures the served
    # site content — the "here is what we achieved" showcase surfaced in the
    # console's Footholds & C2 panel.
    adapter = _poi_adapter_with_served_page(b"<html><h1>OWNED-DEMO</h1></html>")
    adapter.open_for_testing("poi-1", ["10.5.0.12"])
    eid = engagement_id_for("poi-1")
    sid, finding = _seed_foothold(adapter, "poi-1")

    adapter._capture_proof_of_impact("poi-1", sid, finding)
    view = adapter._session_json(eid, sid)

    # loot auto-ran over the bounded command set (test-auth → post-ex autonomous)
    assert [row["command"] for row in view["loot"]] == list(adapter._LOOT_COMMANDS)
    assert view["loot"][0]["output"] == "out:id"
    # captured site content = the live page served by the compromised host
    assert view["site_content"]["status"] == 200
    assert view["site_content"]["url"] == "http://10.5.0.12/"
    assert "OWNED-DEMO" in view["site_content"]["snippet"]


def test_proof_of_impact_skips_loot_without_postex_authorization() -> None:
    # Fail-safe: on a read-only signed scope (post-ex NOT pre-authorized) the
    # showcase never blocks on a human gate — it skips loot entirely, while still
    # capturing the scope-enforced site content.
    adapter = _poi_adapter_with_served_page(b"<html>read-only</html>")
    _open_signed(adapter, "poi-2")  # safe-active → post-ex gated, not autonomous
    eid = engagement_id_for("poi-2")
    sid, finding = _seed_foothold(adapter, "poi-2")

    adapter._capture_proof_of_impact("poi-2", sid, finding)
    view = adapter._session_json(eid, sid)
    assert view["loot"] == []  # no autonomous post-ex → no auto-loot (no gate block)
    assert view["site_content"]["status"] == 200  # read-only site GET still captured


def test_attack_tree_empty_safe_when_closed(adapter: EngineAdapter) -> None:
    t = adapter.attack_tree("never-opened")
    assert t == {"phases": [], "nodes": [], "edges": [], "summary": {}}


def test_attack_tree_surfaces_live_foothold_with_proof() -> None:
    # The whole-breach tree carries a live foothold node (from sessions) plus its
    # proof-of-impact as a post-ex child — the showcase inside the tree.
    adapter = _poi_adapter_with_served_page(b"<html>OWNED</html>")
    adapter.open_for_testing("tree-1", ["10.5.0.12"])
    sid, finding = _seed_foothold(adapter, "tree-1")
    adapter._capture_proof_of_impact("tree-1", sid, finding)

    t = adapter.attack_tree("tree-1")
    assert next(p["key"] for p in t["phases"]) == "origin"
    sess = next(n for n in t["nodes"] if n["kind"] == "session")
    assert sess["phase"] == "foothold" and sess["host"] == "10.5.0.12"
    loot = next(n for n in t["nodes"] if n["kind"] == "loot")
    assert loot["phase"] == "post-ex"
    assert "OWNED" in loot["detail"]["site_content"]["snippet"]
    assert t["summary"]["live_footholds"] == 1
    # a real edge links the foothold to its loot showcase
    assert {"source": sess["id"], "target": loot["id"], "status": "confirmed"} in t["edges"]


def test_campaign_status_kill_chain_shape_and_progression(adapter: EngineAdapter) -> None:
    _open_signed(adapter, "cs-1")
    st = adapter.campaign_status("cs-1")
    keys = [s["key"] for s in st["stages"]]
    assert keys == ["recon", "confirm", "foothold", "escalate", "lateral", "objective"]
    assert st["running"] is False
    # recon not done until an asset is discovered
    assert next(s for s in st["stages"] if s["key"] == "recon")["status"] in ("active", "pending")
    adapter.sense("cs-1", ["10.5.0.10"])  # real recon → an asset appears
    st2 = adapter.campaign_status("cs-1")
    assert next(s for s in st2["stages"] if s["key"] == "recon")["status"] == "done"


def test_campaign_status_empty_when_closed(adapter: EngineAdapter) -> None:
    st = adapter.campaign_status("never")
    assert st["running"] is False
    assert all(s["status"] == "pending" for s in st["stages"])


def test_run_campaign_completes_and_records(adapter: EngineAdapter) -> None:
    _open_signed(adapter, "camp-1")
    outcome = adapter.run_campaign("camp-1", ["10.5.0.10"], max_rounds=1)
    # mock model → loops degrade → campaign converges without reaching DA, but the
    # governance objects are real and the run is recorded + audited.
    assert outcome.stop_reason
    assert outcome.audit_intact is True
    assert any(r["agent_name"] == "Adversary Campaign" for r in adapter.agent_runs("camp-1"))


# distcc on 3632 — a classically-exploitable service nmap's top-1000 default
# misses, so the exploit feed must scan for it explicitly (pilot fix #1b).
_DISTCC_NMAP_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap">
 <host>
  <status state="up"/>
  <address addr="10.5.0.12" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="3632">
     <state state="open"/>
     <service name="distccd" product="distccd" version="v1"/>
   </port>
  </ports>
 </host>
</nmaprun>
"""


def _exploit_adapter() -> EngineAdapter:
    """Adapter whose sandbox reports distcc open + a Metasploit session opening."""

    settings = Settings(
        env="test", model_mock=True, audit_backend=AuditBackend.MEMORY,
        eventbus_backend=EventBusBackend.MEMORY, sandbox_backend=SandboxBackend.NOOP,
    )
    sb = FakeSandbox()
    sb.set_response("nmap", SandboxResult(0, _DISTCC_NMAP_XML, b"", 0.05, "fake"))
    # The metasploit wrapper invokes msfconsole by full path; the fake sandbox
    # keys on the executable basename (see logical_tool), so respond to msfconsole.
    sb.set_response("msfconsole", SandboxResult(
        0, b"[*] Command shell session 1 opened (10.5.0.99:4444 -> 10.5.0.12:41000)\n",
        b"", 0.1, "fake"))
    audit = AuditLog(MemoryAuditBackend())
    engine = Engine(
        settings, audit=audit, event_bus=InMemoryEventBus(),
        gateway=ModelGateway(settings=settings, provider=MockProvider(), audit=audit),
        sandbox=sb, registry=default_registry(),
    )
    return EngineAdapter(engine)


def test_network_service_exploit_lands_confirmed_rce_autonomously() -> None:
    # Pilot #1b: Full Attack's non-web foothold path. An exploit-intensity signed
    # scope pre-authorizes exploit_confirm (Tier ≥ 1), so the curated port scan
    # surfaces distcc and the Metasploit module confirms RCE without a human gate.
    adapter = _exploit_adapter()
    scope = scope_from_roe(
        "exp-1", {"scope_allowlist": ["10.5.0.0/24"], "max_intensity": "exploit"},
        authorized_by="ciso@x", signature="signed-1",
    )
    adapter.open(scope)
    assert scope.roe.read_only is False  # exploitation needs a mutating RoE

    confirmed = adapter._exploit_network_services("exp-1")
    assert confirmed == 1  # the distcc module opened a session → CONFIRMED

    eng = adapter.engagement("exp-1")
    # exploit records a VERIFIED rce finding; correlate finalises it to CONFIRMED.
    eng.correlate()
    rce = [f for f in eng.store.findings(FindingState.CONFIRMED) if f.type == "rce"]
    assert len(rce) == 1
    assert rce[0].metadata.get("confirmed_by") == "metasploit_exploit_v1"
    # and it is a foothold-capable command-execution finding.
    assert adapter._is_foothold_capable(rce[0]) or rce[0].type == "rce"


def test_network_exploit_gates_without_authorization() -> None:
    # Fail-safe: a read-only (non-exploit) scope must NOT autonomously exploit —
    # the mutating Metasploit run is refused, so no RCE is confirmed.
    adapter = _exploit_adapter()
    scope = scope_from_roe(
        "exp-2", {"scope_allowlist": ["10.5.0.0/24"], "max_intensity": "safe-active"},
        authorized_by="ciso@x", signature="signed-2",
    )
    adapter.open(scope)
    assert scope.roe.read_only is True
    confirmed = adapter._exploit_network_services("exp-2")
    assert confirmed == 0
    eng = adapter.engagement("exp-2")
    assert [f for f in eng.store.findings(FindingState.CONFIRMED) if f.type == "rce"] == []


def test_autolaunch_footholds_skips_without_authorization() -> None:
    # Pilot #2 guard: the autonomous campaign only lands footholds when the scope
    # pre-authorizes establish_foothold (Tier ≥ 1). A read-only scope must skip
    # (never block on a human gate) and open no session.
    adapter = _exploit_adapter()
    scope = scope_from_roe(
        "fh-1", {"scope_allowlist": ["10.5.0.0/24"], "max_intensity": "safe-active"},
        authorized_by="c", signature="s",
    )
    adapter.open(scope)
    # even with a confirmed foothold-capable finding present, no auth → no session
    eng = adapter.engagement("fh-1")
    f = Finding(
        engagement_id="eng-fh-1", asset="10.5.0.12", type="command-injection",
        title="cmdi", proposed_by="t", metadata={"param": "host", "method": "GET"},
    )
    stored = eng.store.propose_finding(f, emitted_by="t")
    eng.store.promote_finding(stored.id, FindingState.VERIFIED, verified_by="o", emitted_by="t")
    eng.store.promote_finding(stored.id, FindingState.CONFIRMED, emitted_by="t")
    assert adapter._autolaunch_footholds("fh-1") == []


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


# ── governance / lifecycle audit (Slice 1) ────────────────────────────────────

def test_record_governance_lands_on_the_real_chain_before_open(
    adapter: EngineAdapter,
) -> None:
    """Signing a DRAFT engagement (never opened) is still audited, attributed to
    the real operator, and the hash chain stays valid."""

    adapter.record_governance(
        "acme-gov", actor="ciso@acme.example", action="roe.signed",
        payload={"version": 1},
    )
    events = adapter.audit_events("acme-gov")
    assert len(events) == 1
    ev = events[0]
    assert ev["event_type"] == "roe.signed"
    assert ev["actor"] == "operator"          # coarse lane the console colours by
    assert ev["actor_id"] == "ciso@acme.example"  # real identity preserved
    assert adapter.audit_verify("acme-gov")["valid"] is True


def test_governance_events_isolated_per_engagement(adapter: EngineAdapter) -> None:
    adapter.record_governance("eng-a", actor="op@x", action="engagement.activated")
    adapter.record_governance("eng-b", actor="op@x", action="engagement.paused")
    a = [e["event_type"] for e in adapter.audit_events("eng-a")]
    b = [e["event_type"] for e in adapter.audit_events("eng-b")]
    assert a == ["engagement.activated"]
    assert b == ["engagement.paused"]


def test_audit_actor_lanes_are_derived_from_action() -> None:
    from attack_engine.api.serialize import _actor_role

    assert _actor_role("engagement.activated", "op@x") == "operator"
    assert _actor_role("roe.signed", "op@x") == "operator"
    assert _actor_role("tool.run", "engine-api-service") == "agent"
    assert _actor_role("model.call", "engine-api-service") == "agent"
    assert _actor_role("approval.approved", "boss@x") == "approver"
    assert _actor_role("something.else", "system") == "system"


# ── RoE → Scope mapping completeness (Slice 2) ────────────────────────────────

def test_scope_from_roe_maps_denylist_allowed_tools_and_window_start() -> None:
    scope = scope_from_roe(
        "acme-roe",
        {
            "scope_allowlist": ["10.5.0.0/24", "app.range"],
            "scope_denylist": ["10.5.0.5", "fragile.range"],
            "allowed_tools": ["nmap", "httpx"],
            "max_intensity": "safe-active",
            "window_start": "2020-01-01T00:00:00Z",
            "window_end": "2030-01-01T00:00:00Z",
        },
        authorized_by="ciso@acme.example",
        signature="signed-xyz",
    )
    assert "10.5.0.5/32" in scope.denied_cidrs      # bare IP → /32
    assert "fragile.range" in scope.denied_hosts
    assert scope.roe.allowed_tools == frozenset({"nmap", "httpx"})
    assert scope.starts_at is not None
    assert scope.expires_at is not None


# ── remediation lifecycle: propose fix → re-test (Slice 4) ────────────────────

def _open_with_cve_finding(adapter: EngineAdapter) -> tuple[str, str]:
    scope = scope_from_roe(
        "rem-eng", {"scope_allowlist": ["10.0.4.0/24"], "max_intensity": "recon"},
        authorized_by="a", signature="s",
    )
    eng = adapter.open(scope)
    finding = Finding(
        engagement_id=eng.scope.engagement_id, asset="10.0.4.12",
        type="CVE-2020-0001", service="vsftpd/2.3.4",
        state=FindingState.CONFIRMED, priority=Priority.HIGH,
        reachable=True, exploit_prob=0.8, metadata={"port": 21},
        verified_by="cve_interval_v1",
    )
    eng.store.propose_finding(finding)
    return "rem-eng", finding.id


def test_remediate_proposes_control_and_marks_remediating(adapter: EngineAdapter) -> None:
    eid, fid = _open_with_cve_finding(adapter)
    rem = adapter.remediate_finding(fid, actor="op@acme.example")
    assert rem["finding_id"] == fid
    assert rem["kind"] in {"patch", "ticket", "config", "mitigation"}
    # The console now shows the finding as remediating.
    row = next(f for f in adapter.findings(eid) if f["id"] == fid)
    assert row["status"] == "remediating"
    # It is audited on the real chain.
    actions = [e["event_type"] for e in adapter.audit_events(eid)]
    assert "finding.remediation_proposed" in actions
    # Idempotent — re-proposing returns the same remediation.
    assert adapter.remediate_finding(fid, actor="op@acme.example")["id"] == rem["id"]


def test_retest_reruns_check_and_updates_status(adapter: EngineAdapter) -> None:
    eid, fid = _open_with_cve_finding(adapter)
    adapter.remediate_finding(fid, actor="op@acme.example")
    result = adapter.retest_finding(fid, actor="op@acme.example")
    assert isinstance(result["fixed"], bool)
    assert result["closed"] == result["fixed"]
    row = next(f for f in adapter.findings(eid) if f["id"] == fid)
    assert row["status"] == ("closed" if result["fixed"] else "retest")
    assert row.get("retest") is not None
    actions = [e["event_type"] for e in adapter.audit_events(eid)]
    assert "finding.retest" in actions


def test_remediate_unknown_finding_raises(adapter: EngineAdapter) -> None:
    with pytest.raises(AttackEngineError, match="not found"):
        adapter.remediate_finding("nope", actor="op@acme.example")


# ── CVE cache + refresh (Slice 5) ─────────────────────────────────────────────

def test_cve_cache_returns_loaded_records(adapter: EngineAdapter) -> None:
    cves = adapter.cve_cache()
    assert isinstance(cves, list)
    assert cves, "seed feed should expose at least one CVE"
    row = cves[0]
    assert row["cve_id"] == row["id"]
    for key in ("product", "cvss", "kev", "summary", "exploit_known"):
        assert key in row


def test_refresh_cve_rebuilds_feed_and_audits(adapter: EngineAdapter) -> None:
    scope = scope_from_roe(
        "cve-eng", {"scope_allowlist": ["10.0.4.0/24"], "max_intensity": "recon"},
        authorized_by="a", signature="s",
    )
    adapter.open(scope)
    out = adapter.refresh_cve("cve-eng", actor="op@acme.example")
    assert out["records"] >= 1
    assert out["source"] in {"files", "seed"}
    actions = [e["event_type"] for e in adapter.audit_events("cve-eng")]
    assert "cve.refreshed" in actions


# ── model gateway: playground + Red Scope copilot (Slice 7) ───────────────────

def test_model_infer_routes_through_gateway(adapter: EngineAdapter) -> None:
    out = adapter.model_infer(
        messages=[{"role": "user", "content": "summarize the recon"}],
        sensitivity="internal", actor="op@acme.example",
    )
    assert out["text"]  # mock provider returns something
    assert "route" in out
    assert set(out["usage"]) == {"token_in", "token_out", "latency_ms", "cost"}
    assert out["redaction_applied"] is False


def test_model_infer_sensitive_forces_local(adapter: EngineAdapter) -> None:
    out = adapter.model_infer(
        messages=[{"role": "user", "content": "handle this secret"}],
        sensitivity="sensitive", actor="op@acme.example",
    )
    assert out["route"] == "local"          # SEC-05: sensitive pinned local
    assert out["redaction_applied"] is True


def test_red_scope_chat_replies(adapter: EngineAdapter) -> None:
    out = adapter.red_scope_chat(
        message="what should I do next?",
        history=[{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}],
        actor="op@acme.example",
    )
    assert isinstance(out["reply"], str) and out["reply"]


def test_save_red_scope_agent_returns_id(adapter: EngineAdapter) -> None:
    agent = adapter.save_red_scope_agent(
        {"name": "Kerberoast Copilot", "system": "focus on AD"}, actor="op@acme.example"
    )
    assert agent["id"]
    assert agent["name"] == "Kerberoast Copilot"
    assert agent["created_by"] == "op@acme.example"


# ── raw invocation output + honest counts (Slice 8) ───────────────────────────

def test_invocation_raw_returns_sandbox_output(adapter: EngineAdapter) -> None:
    scope = scope_from_roe(
        "inv-eng", {"scope_allowlist": ["10.5.0.0/24"], "max_intensity": "recon"},
        authorized_by="a", signature="s",
    )
    adapter.open(scope)
    adapter.sense("inv-eng", ["10.5.0.10"])
    invs = adapter.invocations("inv-eng")
    assert invs, "recon should have produced tool invocations"
    detail = adapter.invocation_raw(invs[0]["id"])
    assert detail is not None
    assert "raw" in detail
    assert detail["action"].startswith("tool.")


def test_invocation_raw_unknown_returns_none(adapter: EngineAdapter) -> None:
    assert adapter.invocation_raw("does-not-exist") is None
