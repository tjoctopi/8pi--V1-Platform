"""Declarative agent spec — the Agent Builder unit (spec §6.1).

An agent is data, not code: a role archetype plus a tool binding, model tier,
scope reference, guardrails, and stop conditions. Adding "another way of
attacking" is registering a tool wrapper and listing it here — never cloning
an agent (rule #3). No model is named here; only a *tier*, resolved by the
BYOM gateway (rule #4).
"""

from __future__ import annotations

from enum import Enum

from pydantic import Field, model_validator

from .common import StrictModel


class Archetype(str, Enum):
    """The five reasoning roles. Seven agents are built from these."""

    RECON = "recon_tool_driver"
    WEB = "web_tool_driver"
    EXPLOIT = "exploit_tool_driver"
    CORRELATOR = "correlator"
    REMEDIATOR = "remediator"
    PLANNER = "planner"
    BLUE = "defensive_triage"


class ModelTier(str, Enum):
    """Abstract model tiers resolved by the gateway — never a fixed model."""

    FRONTIER = "frontier"
    LOCAL = "local"


#: Archetypes that drive security tools and therefore must list at least one.
#: Reasoning roles (planner, correlator, remediator, blue) need none.
_TOOL_DRIVER_ARCHETYPES = frozenset({Archetype.RECON, Archetype.WEB, Archetype.EXPLOIT})


class Guardrails(StrictModel):
    read_only_default: bool = True
    #: Actions that require a human gate before the agent may perform them.
    require_gate_before: tuple[str, ...] = Field(default_factory=tuple)
    #: Whether the web agent *actively* screens injection points (sends read-only
    #: differential probes to confirm exploitability). Intelligence-gathering
    #: ("capture only") turns this off: it still enumerates and records every
    #: injection point as an attack lead, but does not probe them — faster and
    #: lower-touch on the target. Confirmation runs default it on.
    active_injection_screen: bool = True


class StopConditions(StrictModel):
    """Every agent must declare when to stop — the Orchestrator enforces these."""

    max_findings: int = Field(default=200, ge=1)
    max_runtime_sec: int = Field(default=3600, ge=1)
    max_tool_calls: int = Field(default=500, ge=1)
    #: Behaviour on an out-of-scope target: "halt" (freeze) or "skip".
    on_out_of_scope: str = Field(default="halt", pattern=r"^(halt|skip)$")


class AgentSpec(StrictModel):
    """A single declarative agent definition, loaded from ``specs/*.yaml``."""

    id: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    archetype: Archetype
    goal: str = Field(min_length=1)
    model_tier: ModelTier = ModelTier.LOCAL
    #: Tool names resolved from the Tool Registry at runtime.
    tools: tuple[str, ...] = Field(default_factory=tuple)
    #: RoE + allowlist reference; enforced at the Tool Runner.
    scope_ref: str = Field(pattern=r"^eng(agement)?-[A-Za-z0-9_-]+$")
    guardrails: Guardrails = Field(default_factory=Guardrails)
    stop_conditions: StopConditions = Field(default_factory=StopConditions)

    @model_validator(mode="after")
    def _tool_drivers_declare_tools(self) -> AgentSpec:
        if self.archetype in _TOOL_DRIVER_ARCHETYPES and not self.tools:
            raise ValueError(
                f"tool-driver agent {self.id!r} ({self.archetype.value}) declares no tools"
            )
        return self
