"""Rules-of-Engagement evaluation.

The RoE lives in the :class:`~attack_engine.schemas.scope.Scope`; this evaluator
answers the yes/no questions the Tool Runner asks on every invocation:

* Is this tool forbidden for the engagement?
* Does this action require a human gate?
* Is a mutating tool profile allowed under a read-only engagement?

Kept separate from scope *matching* (CIDR/host) so the two concerns —
"where may we act" vs. "what may we do" — stay independently testable.
"""

from __future__ import annotations

from ..schemas.scope import Scope


class RoEEvaluator:
    """Pure, side-effect-free RoE decisions for one engagement."""

    def __init__(self, scope: Scope) -> None:
        self._roe = scope.roe

    def is_tool_forbidden(self, tool: str) -> bool:
        return tool in self._roe.forbidden_tools

    def requires_gate(self, action: str) -> bool:
        return action in self._roe.gated_actions

    def allows_mutation(self, mutating: bool) -> bool:
        """A mutating profile is allowed only if the engagement is not read-only."""

        if not mutating:
            return True
        return not self._roe.read_only

    def within_call_budget(self, calls_so_far: int) -> bool:
        cap = self._roe.max_total_tool_calls
        return cap == 0 or calls_so_far < cap

    def licensed_tool_enabled(self, tool: str) -> bool:
        """Whether a commercial tool has procurement sign-off for this engagement."""

        return tool in self._roe.licensed_tools_enabled
