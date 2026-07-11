"""Agent base — the runtime that runs a role archetype from a declarative spec.

The base class owns everything common to every archetype: the run lifecycle
(``agent.started`` / ``agent.stopped`` events + audit), stop-condition tracking
(max findings / runtime / tool calls), and the *safe* tool-call helper that
routes through the scope-enforcing Tool Runner and applies the spec's
out-of-scope policy. Archetypes implement only :meth:`_execute` — their actual
reasoning role.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field

from ..errors import (
    SandboxError,
    ScopeViolationError,
    StopConditionReached,
    ToolExecutionError,
)
from ..logging import get_logger
from ..schemas.agentspec import AgentSpec
from ..schemas.events import Event, EventType
from ..schemas.tools import ToolProfile, ToolResult
from .context import AgentContext

_log = get_logger("agent")


@dataclass
class AgentReport:
    """Outcome of one agent run."""

    agent_id: str
    engagement_id: str
    stopped_reason: str = "completed"
    tool_calls: int = 0
    findings_proposed: int = 0
    assets_found: int = 0
    duration_sec: float = 0.0
    skipped_targets: list[str] = field(default_factory=list)


class Agent(ABC):
    """Executable agent built from an :class:`AgentSpec` + :class:`AgentContext`."""

    def __init__(
        self,
        spec: AgentSpec,
        ctx: AgentContext,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.spec = spec
        self.ctx = ctx
        self._clock = clock
        self._started_at = 0.0
        self._tool_calls = 0
        self._findings = 0
        self._assets = 0
        self._skipped: list[str] = []

    # --- lifecycle ------------------------------------------------------------

    def run(self, targets: list[str]) -> AgentReport:
        """Run the agent over ``targets`` and return its report.

        Stop conditions and scope refusals produce a clean, audited stop — never
        an unhandled crash. Any other exception propagates (the Orchestrator
        retries idempotently; blackboard state is safe).
        """

        self._started_at = self._clock()
        self._emit(EventType.AGENT_STARTED, payload={"targets": len(targets)})
        self.ctx.audit.append(
            engagement_id=self.ctx.engagement_id,
            actor=self.spec.id,
            action="agent.start",
            payload={"archetype": self.spec.archetype.value, "targets": targets},
        )
        reason = "completed"
        try:
            self._execute(targets)
        except StopConditionReached as stop:
            reason = stop.condition
            _log.info("agent stopped", agent=self.spec.id, reason=reason)
        report = AgentReport(
            agent_id=self.spec.id,
            engagement_id=self.ctx.engagement_id,
            stopped_reason=reason,
            tool_calls=self._tool_calls,
            findings_proposed=self._findings,
            assets_found=self._assets,
            duration_sec=round(self._clock() - self._started_at, 4),
            skipped_targets=list(self._skipped),
        )
        self._emit(
            EventType.AGENT_STOPPED,
            payload={
                "reason": reason,
                "tool_calls": report.tool_calls,
                "findings": report.findings_proposed,
                "assets": report.assets_found,
            },
        )
        self.ctx.audit.append(
            engagement_id=self.ctx.engagement_id,
            actor=self.spec.id,
            action="agent.stop",
            payload={"reason": reason, "tool_calls": report.tool_calls},
        )
        return report

    @abstractmethod
    def _execute(self, targets: list[str]) -> None:
        """The archetype's role logic. Use :meth:`run_tool` for all tool calls."""

    # --- stop conditions ------------------------------------------------------

    def _check_stop_conditions(self) -> None:
        sc = self.spec.stop_conditions
        if self._findings >= sc.max_findings:
            raise StopConditionReached("max_findings", str(sc.max_findings))
        if self._tool_calls >= sc.max_tool_calls:
            raise StopConditionReached("max_tool_calls", str(sc.max_tool_calls))
        elapsed = self._clock() - self._started_at
        if elapsed >= sc.max_runtime_sec:
            raise StopConditionReached("max_runtime_sec", f"{elapsed:.0f}s")

    # --- safe tool execution --------------------------------------------------

    def run_tool(
        self, tool: str, target: str, profile: ToolProfile | None = None
    ) -> ToolResult | None:
        """Run a tool through the scope-enforcing boundary, honouring stop/scope.

        Returns ``None`` when the target is out of scope and the spec's policy is
        ``skip``; raises :class:`StopConditionReached` when the policy is
        ``halt`` or a stop condition trips.
        """

        if tool not in self.spec.tools:
            raise ValueError(
                f"agent {self.spec.id!r} may not use tool {tool!r} (not in spec)"
            )
        self._check_stop_conditions()
        try:
            result = self.ctx.tool_runner.run(tool, target, profile)
        except ScopeViolationError:
            if self.spec.stop_conditions.on_out_of_scope == "halt":
                raise StopConditionReached("on_out_of_scope", target) from None
            _log.warning("skipping out-of-scope target", agent=self.spec.id, target=target)
            self._skipped.append(target)
            return None
        except (ToolExecutionError, SandboxError) as exc:
            # A single tool that times out, errors, or whose sandbox can't run
            # must degrade — never abort the engagement. The blackboard keeps
            # what other tools found; the Orchestrator can retry idempotently.
            _log.warning("tool degraded (execution error)", agent=self.spec.id,
                         tool=tool, target=target, error=str(exc))
            self._tool_calls += 1
            return None
        self._tool_calls += 1
        return result

    # --- human gates ----------------------------------------------------------

    def require_gate(
        self, action: str, *, target: str | None = None, summary: str = ""
    ) -> None:
        """Block until a human approves ``action``; raise if denied.

        The authoritative source of *which* actions are gated is the
        human-signed **RoE** (``scope.roe.gated_actions``), not the agent spec.
        An agent spec may *add* gates via ``require_gate_before`` but can never
        remove a RoE-mandated one — a mis-authored or malicious spec cannot
        downgrade governance (rule #2: scope/RoE decides at the boundary, not the
        agent). Fails **closed**: a gated action with no gate wired stops the
        agent. Raises :class:`~attack_engine.errors.GateDeniedError` on denial.
        """

        roe_gated = action in self.ctx.scope.roe.gated_actions
        spec_gated = action in self.spec.guardrails.require_gate_before
        if not (roe_gated or spec_gated):
            return
        if self.ctx.gate is None:
            raise StopConditionReached("gate_unavailable", action)
        self.ctx.gate.require(
            engagement_id=self.ctx.engagement_id,
            gate=action,
            requested_by=self.spec.id,
            target=target,
            summary=summary,
        )

    # --- knowledge-store bookkeeping ------------------------------------------

    def _note_asset(self) -> None:
        self._assets += 1

    def _note_finding(self) -> None:
        self._findings += 1
        self._check_stop_conditions()

    # --- events ---------------------------------------------------------------

    def _emit(self, event: EventType, **kwargs: object) -> None:
        bus = self.ctx.event_bus
        if bus is None:
            return
        bus.publish(
            Event(
                event=event,
                engagement_id=self.ctx.engagement_id,
                emitted_by=self.spec.id,
                **kwargs,
            )
        )
