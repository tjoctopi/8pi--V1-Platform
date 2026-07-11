"""Surface Mapper agent tests — the one safe agent, end to end."""

from __future__ import annotations

from pathlib import Path

import pytest

from attack_engine.agents.loader import build_agent, load_spec
from attack_engine.schemas.events import EventType
from attack_engine.schemas.findings import FindingState
from attack_engine.toolrunner.registry import default_registry

SPECS_DIR = Path(__file__).resolve().parents[2] / "src/attack_engine/agents/specs"


@pytest.fixture
def mapper(ctx):
    spec = load_spec(SPECS_DIR / "surface_mapper.yaml")
    return build_agent(spec, ctx, default_registry())


class TestReconRun:
    def test_discovers_assets_and_services(self, mapper, ctx) -> None:
        report = mapper.run(["10.0.4.12"])
        assets = ctx.store.assets()
        assert len(assets) == 1
        asset = assets[0]
        assert asset.address == "10.0.4.12"
        # nmap fixture: 80 + 3306 open (22 closed → excluded).
        assert {s.port for s in asset.services} == {80, 3306}
        assert report.assets_found == 1

    def test_proposes_findings_for_services_and_web_paths(self, mapper, ctx) -> None:
        mapper.run(["10.0.4.12"])
        findings = ctx.store.findings()
        types = {f.type for f in findings}
        # 2 exposed-service (80, 3306) + 2 web-paths (admin, login from ffuf).
        assert "exposed-service:80/tcp" in types
        assert "exposed-service:3306/tcp" in types
        assert any(t.startswith("web-path:admin") for t in types)
        assert any(t.startswith("web-path:login") for t in types)

    def test_all_findings_start_proposed_not_confirmed(self, mapper, ctx) -> None:
        # Rule #1: recon PROPOSES; nothing is confirmed by the mapper.
        mapper.run(["10.0.4.12"])
        assert ctx.store.findings(FindingState.CONFIRMED) == []
        assert len(ctx.store.findings(FindingState.PROPOSED)) == len(ctx.store.findings())

    def test_web_recon_only_on_web_ports(self, mapper, ctx, fake_sandbox) -> None:
        mapper.run(["10.0.4.12"])
        # ffuf runs shell-wrapped ("sh -c '... ffuf ...'"), so match the script.
        ffuf_calls = [c for c in fake_sandbox.calls if "ffuf" in " ".join(c.argv)]
        # Only port 80 is a web port in the fixture → exactly one ffuf run.
        assert len(ffuf_calls) == 1

    def test_emits_agent_and_tool_events(self, mapper, ctx, bus) -> None:
        events: list = []
        bus.subscribe(events.append)
        mapper.run(["10.0.4.12"])
        types = [e.event for e in events]
        assert EventType.AGENT_STARTED in types
        assert EventType.AGENT_STOPPED in types
        # The recon toolchain (masscan → nmap → httpx → ffuf) completed; at
        # minimum nmap and ffuf must have run and produced completion events.
        completed_tools = {
            e.payload.get("tool") for e in events if e.event is EventType.TOOL_COMPLETED
        }
        assert {"nmap", "ffuf"} <= completed_tools

    def test_findings_are_reachable_from_entry(self, mapper, ctx) -> None:
        mapper.run(["10.0.4.12"])
        # The scanned asset is reachable, so its findings inherit reachability.
        assert all(f.reachable for f in ctx.store.findings())


class TestGovernance:
    def test_run_is_fully_audited_and_chain_intact(self, mapper, ctx, audit) -> None:
        mapper.run(["10.0.4.12"])
        actions = [e.action for e in audit.entries()]
        assert "agent.start" in actions
        assert "agent.stop" in actions
        # Every tool the mapper drove is audited (masscan/nmap/httpx/ffuf).
        tools_run = {
            e.payload.get("tool") for e in audit.entries() if e.action == "tool.run"
        }
        assert {"nmap", "ffuf"} <= tools_run
        assert "model.decision" in actions  # BYOM summary was audited
        assert audit.verify() is True

    def test_out_of_scope_target_halts_per_spec(self, mapper, ctx, fake_sandbox) -> None:
        # spec on_out_of_scope=halt → the whole run stops at the bad target.
        report = mapper.run(["8.8.8.8", "10.0.4.12"])
        assert report.stopped_reason == "on_out_of_scope"
        # The out-of-scope target was refused before any sandbox execution.
        assert fake_sandbox.calls == []
        assert ctx.store.assets() == []

    def test_agent_cannot_use_tool_not_in_spec(self, mapper) -> None:
        with pytest.raises(ValueError, match="may not use tool"):
            mapper.run_tool("sqlmap", "10.0.4.12")

    def test_tool_timeout_degrades_not_crashes(self, mapper, ctx) -> None:
        # A tool that times out/errors must degrade to None, never abort the run.
        from attack_engine.errors import ToolTimeoutError

        def boom(*_a, **_k):
            raise ToolTimeoutError("nmap", "10.0.4.12", "timeout after 30s")

        ctx.tool_runner.run = boom  # type: ignore[assignment]
        mapper._started_at = mapper._clock()  # simulate an active run
        assert mapper.run_tool("nmap", "10.0.4.12") is None  # degraded, no raise


class TestStopConditions:
    def test_max_findings_stops_run(self, ctx) -> None:
        from attack_engine.agents.loader import build_agent

        spec = load_spec(SPECS_DIR / "surface_mapper.yaml")
        tight = spec.model_copy(
            update={"stop_conditions": spec.stop_conditions.model_copy(
                update={"max_findings": 1}
            )}
        )
        agent = build_agent(tight, ctx, default_registry())
        report = agent.run(["10.0.4.12"])
        assert report.stopped_reason == "max_findings"
        # Stopped early: fewer than the full 4 findings were recorded.
        assert report.findings_proposed <= 2
