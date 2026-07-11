"""Agent spec loading + archetype binding tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from attack_engine.agents.archetypes.recon import SurfaceMapper
from attack_engine.agents.loader import (
    build_agent,
    load_spec,
    load_specs,
    validate_tools,
)
from attack_engine.errors import AgentSpecError
from attack_engine.schemas.agentspec import Archetype
from attack_engine.toolrunner.registry import default_registry

SPECS_DIR = Path(__file__).resolve().parents[2] / "src/attack_engine/agents/specs"


def test_load_shipped_surface_mapper_spec() -> None:
    spec = load_spec(SPECS_DIR / "surface_mapper.yaml")
    assert spec.id == "surface_mapper"
    assert spec.archetype is Archetype.RECON
    # Core recon tools are bound (plus the licensed Nessus, gated by RoE).
    assert {"nmap", "ffuf", "httpx"} <= set(spec.tools)
    assert spec.stop_conditions.on_out_of_scope == "halt"


def test_load_specs_directory() -> None:
    specs = load_specs(SPECS_DIR)
    assert any(s.id == "surface_mapper" for s in specs)


def test_missing_spec_raises() -> None:
    with pytest.raises(AgentSpecError, match="not found"):
        load_spec(SPECS_DIR / "nope.yaml")


def test_invalid_yaml_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: [unclosed")
    with pytest.raises(AgentSpecError):
        load_spec(bad)


def test_spec_with_no_tools_rejected(tmp_path: Path) -> None:
    spec_file = tmp_path / "empty.yaml"
    spec_file.write_text(
        "id: x\narchetype: recon_tool_driver\ngoal: g\nscope_ref: eng-1\ntools: []\n"
    )
    with pytest.raises(AgentSpecError):
        load_spec(spec_file)


def test_validate_tools_flags_unregistered(tmp_path: Path) -> None:
    spec_file = tmp_path / "s.yaml"
    spec_file.write_text(
        "id: x\narchetype: recon_tool_driver\ngoal: g\nscope_ref: eng-1\n"
        "tools: [nmap, nonexistent_tool]\n"
    )
    spec = load_spec(spec_file)
    with pytest.raises(AgentSpecError, match="unregistered"):
        validate_tools(spec, default_registry())


def test_build_agent_returns_correct_archetype(ctx) -> None:
    spec = load_spec(SPECS_DIR / "surface_mapper.yaml")
    agent = build_agent(spec, ctx, default_registry())
    assert isinstance(agent, SurfaceMapper)
