"""The Tool Runner — the one execution boundary every tool passes through.

This is rule #2 made concrete (spec §6.2). A runner is bound to a single
engagement's :class:`~attack_engine.schemas.scope.Scope`; agents call
:meth:`ToolRunner.run` and never anything else. The order of checks is
deliberate and load-bearing:

    1. scope           — radix-trie CIDR / host allowlist   (refuse first)
    2. RoE / tool       — forbidden tool?
    3. resolve wrapper  — name → wrapper (registry)
    4. RoE / mutation   — mutating profile under read-only engagement?
    5. rate limit       — RoE-driven token bucket
    6. sandbox exec     — ephemeral, network-scoped container
    7. audit            — immutable, hash-chained (with raw bytes)
    8. emit completed   — blackboard event for the Orchestrator/Blue Sentry

Every refusal is itself audited and emitted as ``tool.refused`` — an
out-of-scope target leaves a permanent, tamper-evident record.
"""

from __future__ import annotations

from ..errors import (
    RateLimitExceededError,
    RoEViolationError,
    ScopeViolationError,
)
from ..eventbus.base import EventPublisher
from ..governance.audit import AuditLog
from ..governance.roe import RoEEvaluator
from ..logging import get_logger
from ..schemas.events import Event, EventType
from ..schemas.scope import Scope
from ..schemas.tools import ToolProfile, ToolResult
from .ratelimit import RateLimiter
from .registry import ToolRegistry
from .sandbox import NoopSandbox, Sandbox, SandboxSpec
from .scope import Resolver, ScopeEnforcer

_log = get_logger("toolrunner")


class ToolRunner:
    """Scope-enforced, audited execution boundary for one engagement."""

    def __init__(
        self,
        scope: Scope,
        *,
        registry: ToolRegistry,
        audit: AuditLog,
        sandbox: Sandbox | None = None,
        event_bus: EventPublisher | None = None,
        rate_limiter: RateLimiter | None = None,
        resolver: Resolver | None = None,
        network: str = "none",
        actor: str = "toolrunner",
    ) -> None:
        self._scope = scope
        self._registry = registry
        self._audit = audit
        self._sandbox = sandbox or NoopSandbox()
        self._bus = event_bus
        self._enforcer = ScopeEnforcer(scope, resolver=resolver)
        self._limiter = rate_limiter or RateLimiter(scope)
        self._roe = RoEEvaluator(scope)
        self._network = network
        self._actor = actor
        self._call_count = 0

    @property
    def engagement_id(self) -> str:
        return self._scope.engagement_id

    @property
    def call_count(self) -> int:
        return self._call_count

    # --- internals ------------------------------------------------------------

    def _emit(self, event: EventType, **kwargs: object) -> None:
        if self._bus is None:
            return
        self._bus.publish(
            Event(
                event=event,
                engagement_id=self.engagement_id,
                emitted_by=self._actor,
                **kwargs,
            )
        )

    def _refuse(self, tool: str, target: str, reason: str, detail: str) -> None:
        """Audit + emit a refusal. Called before raising the refusal error."""

        entry = self._audit.append(
            engagement_id=self.engagement_id,
            actor=self._actor,
            action="tool.refused",
            target=target,
            payload={"tool": tool, "reason": reason, "detail": detail},
        )
        self._emit(
            EventType.TOOL_REFUSED,
            target=target,
            audit_id=entry.entry_hash,
            payload={"tool": tool, "reason": reason, "detail": detail},
        )
        _log.warning(
            "tool refused",
            tool=tool,
            target=target,
            reason=reason,
            engagement=self.engagement_id,
        )

    # --- the boundary ---------------------------------------------------------

    def run(
        self, tool: str, target: str, profile: ToolProfile | None = None
    ) -> ToolResult:
        """Execute ``tool`` against ``target`` under this engagement's scope.

        Raises :class:`ScopeViolationError`, :class:`RoEViolationError`,
        :class:`RateLimitExceededError`, or a tool/sandbox error — each after
        the refusal has been audited. On success returns a fully populated
        :class:`ToolResult` whose ``audit_id`` links to the immutable record.
        """

        profile = profile or ToolProfile()

        # 1. Scope FIRST — an out-of-scope target never reaches a tool.
        try:
            self._enforcer.check(target)
        except ScopeViolationError as exc:
            self._refuse(tool, target, "scope", exc.reason)
            raise

        # 2. RoE: is this tool forbidden for the engagement?
        if self._roe.is_tool_forbidden(tool):
            self._refuse(tool, target, "forbidden_tool", "tool in RoE denylist")
            raise RoEViolationError(tool, "tool in RoE denylist")

        # 3. Resolve the wrapper (raises ToolNotRegisteredError if unknown).
        wrapper = self._registry.resolve(tool)

        # 3b. Licensed/commercial tool without procurement sign-off? Refuse.
        if wrapper.licensed and not self._roe.licensed_tool_enabled(tool):
            self._refuse(tool, target, "licensed_not_enabled",
                         "commercial tool without procurement sign-off in RoE")
            raise RoEViolationError(tool, "licensed tool not enabled for this engagement")

        # 4. RoE: mutating profile under a read-only engagement?
        if not self._roe.allows_mutation(wrapper.is_mutating(profile)):
            self._refuse(tool, target, "read_only", "mutating profile under read-only RoE")
            raise RoEViolationError(tool, "mutating profile under read-only RoE")

        # RoE: total call budget.
        if not self._roe.within_call_budget(self._call_count):
            self._refuse(tool, target, "call_budget", "engagement tool-call budget exhausted")
            raise RoEViolationError(tool, "engagement tool-call budget exhausted")

        # 5. Rate limit (RoE-driven token bucket).
        try:
            self._limiter.check(tool, target)
        except RateLimitExceededError as exc:
            self._refuse(tool, target, "rate_limit", str(exc))
            raise

        # 6. Ephemeral, network-scoped sandbox execution.
        argv = wrapper.build_argv(target, profile)
        spec = SandboxSpec(
            image=wrapper.default_image,
            argv=argv,
            timeout_sec=wrapper.timeout_for(profile),
            network=self._network,
            mounts=tuple(wrapper.mounts(profile)),
        )
        self._emit(
            EventType.TOOL_STARTED,
            target=target,
            payload={"tool": tool, "preset": profile.preset},
        )
        self._call_count += 1
        sandbox_result = self._sandbox.run(spec)

        # Parse into structured, tool-shaped data.
        parsed = wrapper.parse(target, sandbox_result)

        # 7. Immutable audit with full-fidelity raw output.
        entry = self._audit.append(
            engagement_id=self.engagement_id,
            actor=self._actor,
            action="tool.run",
            target=target,
            payload={
                "tool": tool,
                "preset": profile.preset,
                "argv": argv,
                "exit_code": sandbox_result.exit_code,
                "duration_sec": round(sandbox_result.duration_sec, 4),
                "sandbox": sandbox_result.backend,
            },
            raw=sandbox_result.combined,
        )

        result = ToolResult(
            tool=tool,
            target=target,
            preset=profile.preset,
            raw=sandbox_result.stdout,
            parsed=parsed,
            exit_code=sandbox_result.exit_code,
            audit_id=entry.entry_hash,
            engagement_id=self.engagement_id,
            sandbox=sandbox_result.backend,
        )

        # 8. Completion event for the Orchestrator / Blue Sentry.
        self._emit(
            EventType.TOOL_COMPLETED,
            target=target,
            audit_id=entry.entry_hash,
            payload={"tool": tool, "exit_code": sandbox_result.exit_code, "ok": result.ok},
        )
        return result
