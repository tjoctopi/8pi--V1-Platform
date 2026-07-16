"""ToolRunnerActor — the loop's Act stage, bound to the Tool Runner boundary.

The reasoning loop proposes an action; this Actor turns it into a real tool
invocation through the scope-enforcing :class:`~attack_engine.toolrunner.runner.ToolRunner`
(rule #2 — scope/rate/RoE live at the boundary, never here). It degrades safely:
an out-of-scope target or a tool/sandbox failure becomes an unproductive
``ActionOutcome`` (``ok=False``), so the loop's Reflector can adapt or give up
rather than crash. Reusable by every specialist — the actor doesn't know or care
whether the tool is nmap or bloodhound.
"""

from __future__ import annotations

from ..errors import (
    RateLimitExceededError,
    RoEViolationError,
    SandboxError,
    ScopeViolationError,
    ToolExecutionError,
)
from ..logging import get_logger
from ..schemas.tools import ToolProfile
from ..toolrunner.runner import ToolRunner
from .actions import ActionOutcome, ProposedAction

_log = get_logger("agent.tool_actor")


class ToolRunnerActor:
    """Executes a :class:`ProposedAction` as a governed tool run."""

    def __init__(self, tool_runner: ToolRunner) -> None:
        self._runner = tool_runner

    def act(self, action: ProposedAction) -> ActionOutcome:
        if not action.target:
            return ActionOutcome(ok=False, summary=f"{action.tool}: no target given")
        profile = ToolProfile(args=dict(action.params))
        try:
            result = self._runner.run(action.tool, action.target, profile)
        except ScopeViolationError as exc:
            _log.warning("actor: out of scope", tool=action.tool, target=action.target)
            return ActionOutcome(ok=False, summary=f"out-of-scope: {exc.reason}")
        except (RoEViolationError, RateLimitExceededError) as exc:
            return ActionOutcome(ok=False, summary=f"refused: {exc}")
        except (ToolExecutionError, SandboxError) as exc:
            _log.warning("actor: tool degraded", tool=action.tool, error=str(exc))
            return ActionOutcome(ok=False, summary=f"degraded: {exc}")

        summary = (
            f"{action.tool} on {action.target}: exit={result.exit_code} "
            f"({'ok' if result.ok else 'empty'})"
        )
        return ActionOutcome(ok=result.ok, summary=summary, raw=result)
