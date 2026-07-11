"""Load declarative agent specs and instantiate the right archetype.

An :class:`~attack_engine.schemas.agentspec.AgentSpec` is loaded from YAML and
validated, its tools are checked against the registry (fail fast on a typo or an
unregistered tool), and it is bound to the archetype class that implements its
role. This is the "Agent Builder": data in, executable agent out.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from ..errors import AgentSpecError
from ..schemas.agentspec import AgentSpec, Archetype
from ..toolrunner.registry import ToolRegistry
from .archetypes.converter import Converter
from .archetypes.exploit import ExploitConfirmer
from .archetypes.recon import SurfaceMapper
from .archetypes.web import WebInquisitor
from .base import Agent
from .context import AgentContext

#: Archetype → implementing class. New roles register here (rule #3).
_ARCHETYPE_REGISTRY: dict[Archetype, type[Agent]] = {
    Archetype.RECON: SurfaceMapper,
    Archetype.WEB: WebInquisitor,
    Archetype.EXPLOIT: ExploitConfirmer,
    Archetype.REMEDIATOR: Converter,
}


def load_spec(path: str | Path) -> AgentSpec:
    """Parse and validate a single agent spec YAML file."""

    p = Path(path)
    if not p.exists():
        raise AgentSpecError(f"agent spec not found: {p}")
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise AgentSpecError(f"invalid YAML in {p}: {exc}") from exc
    if not isinstance(data, dict):
        raise AgentSpecError(f"agent spec {p} must be a mapping")
    try:
        return AgentSpec.model_validate(data)
    except Exception as exc:
        raise AgentSpecError(f"invalid agent spec {p}: {exc}") from exc


def load_specs(directory: str | Path) -> list[AgentSpec]:
    """Load every ``*.yaml`` spec in a directory."""

    d = Path(directory)
    if not d.is_dir():
        raise AgentSpecError(f"not a directory: {d}")
    return [load_spec(f) for f in sorted(d.glob("*.yaml"))]


def validate_tools(spec: AgentSpec, registry: ToolRegistry) -> None:
    """Ensure every tool the spec lists is registered."""

    unknown = [t for t in spec.tools if not registry.is_registered(t)]
    if unknown:
        raise AgentSpecError(
            f"agent {spec.id!r} references unregistered tools: {unknown}"
        )


def build_agent(spec: AgentSpec, ctx: AgentContext, registry: ToolRegistry) -> Agent:
    """Instantiate the archetype implementation for ``spec``."""

    validate_tools(spec, registry)
    agent_cls = _ARCHETYPE_REGISTRY.get(spec.archetype)
    if agent_cls is None:
        raise AgentSpecError(
            f"no implementation registered for archetype {spec.archetype.value!r}"
        )
    return agent_cls(spec, ctx)
