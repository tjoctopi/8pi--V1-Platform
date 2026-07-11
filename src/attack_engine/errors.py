"""Exception hierarchy for the engine.

A single root (:class:`AttackEngineError`) lets callers catch everything the
engine raises without swallowing unrelated bugs. Security-relevant refusals
(out-of-scope, rate-limited, gate-denied) get their own types because they are
*expected* control-flow, not faults, and must be distinguishable in the audit
log.
"""

from __future__ import annotations


class AttackEngineError(Exception):
    """Root of all engine-raised errors."""


# --- Scope / RoE enforcement (Tool Runner boundary) ----------------------------


class ScopeViolationError(AttackEngineError):
    """A target was rejected because it is outside the engagement scope.

    This is raised *before* any tool executes. It is expected control flow —
    the correct, safe outcome for an out-of-scope target — and is always
    audited.
    """

    def __init__(self, target: str, reason: str = "target not in allowlist") -> None:
        self.target = target
        self.reason = reason
        super().__init__(f"scope violation for {target!r}: {reason}")


class RateLimitExceededError(AttackEngineError):
    """A tool/target pair exceeded its RoE-driven rate limit."""

    def __init__(self, tool: str, target: str, limit_per_sec: float) -> None:
        self.tool = tool
        self.target = target
        self.limit_per_sec = limit_per_sec
        super().__init__(
            f"rate limit exceeded for tool={tool!r} target={target!r} "
            f"(limit={limit_per_sec}/s)"
        )


# --- Governance / gates --------------------------------------------------------


class RoEViolationError(AttackEngineError):
    """An action was refused by the Rules of Engagement.

    Raised for a forbidden tool or a mutating profile under a read-only
    engagement. Like a scope violation, this is expected, audited control flow
    — the safe refusal — not a fault.
    """

    def __init__(self, tool: str, reason: str) -> None:
        self.tool = tool
        self.reason = reason
        super().__init__(f"RoE refusal for tool {tool!r}: {reason}")


class GateDeniedError(AttackEngineError):
    """A human-in-the-loop gate denied (or timed out on) an action."""

    def __init__(self, gate: str, reason: str = "denied") -> None:
        self.gate = gate
        self.reason = reason
        super().__init__(f"gate {gate!r} denied: {reason}")


class AuditIntegrityError(AttackEngineError):
    """The audit hash chain failed verification — possible tampering."""


class AuthorizationError(AttackEngineError):
    """A principal lacks the permission (or engagement access) for an action.

    Like a scope violation, this is expected, audited control flow — the safe
    refusal — not a fault.
    """

    def __init__(self, principal: str, permission: str, detail: str = "") -> None:
        self.principal = principal
        self.permission = permission
        msg = f"principal {principal!r} not authorized for {permission!r}"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


# --- Tool Runner ---------------------------------------------------------------


class ToolNotRegisteredError(AttackEngineError):
    """A tool name could not be resolved from the registry."""

    def __init__(self, tool: str) -> None:
        self.tool = tool
        super().__init__(f"tool {tool!r} is not registered")


class ToolExecutionError(AttackEngineError):
    """A tool failed to execute inside the sandbox."""

    def __init__(self, tool: str, target: str, detail: str) -> None:
        self.tool = tool
        self.target = target
        self.detail = detail
        super().__init__(f"tool {tool!r} failed on {target!r}: {detail}")


class ToolTimeoutError(ToolExecutionError):
    """A tool exceeded its wall-clock timeout in the sandbox."""


class SandboxError(AttackEngineError):
    """The sandbox backend could not provision or run a container."""


# --- Knowledge store -----------------------------------------------------------


class UnknownNodeError(AttackEngineError):
    """A referenced graph node does not exist."""


# --- Model gateway -------------------------------------------------------------


class ModelGatewayError(AttackEngineError):
    """A model completion failed after retries, or was misconfigured."""


# --- Agent runtime -------------------------------------------------------------


class AgentSpecError(AttackEngineError):
    """A declarative agent spec is invalid or references unknown resources."""


class StopConditionReached(AttackEngineError):
    """An agent hit a declared stop condition and halted cleanly."""

    def __init__(self, condition: str, detail: str = "") -> None:
        self.condition = condition
        self.detail = detail
        msg = f"stop condition reached: {condition}"
        if detail:
            msg += f" ({detail})"
        super().__init__(msg)
