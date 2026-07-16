"""Objective-driven controller (spec §3) — the adaptive replacement for the
fixed 8-phase orchestrator.

Where :class:`~attack_engine.orchestrator.orchestrator.Orchestrator` runs the
same phases in the same order every time, the controller pursues a named
:class:`~attack_engine.orchestrator.objective.Objective`: it drives the
reasoning loop toward the goal and stops the moment a deterministic check says
the goal is met (or the loop stalls / runs out of budget). Action *selection* is
the loop's expected-value ranking; the controller adds the goal, the
satisfaction gate, and — in later phases — dispatch across multiple specialists.

The legacy Orchestrator is kept intact and selectable (``AE_ORCHESTRATOR``); this
is added alongside it, not in place of it, until it has proven out on the range.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..agents.actions import ReasoningResult
from ..agents.reasoning import ReasoningLoop
from ..gateway.budget import TokenBudget
from ..knowledge.worldmodel import WorldModel
from ..logging import get_logger
from .objective import Objective

_log = get_logger("orchestrator.controller")


@dataclass
class ControllerResult:
    """Outcome of pursuing an objective."""

    objective_met: bool
    reasoning: ReasoningResult

    @property
    def stop_reason(self) -> str:
        return self.reasoning.stop_reason

    @property
    def iterations(self) -> int:
        return self.reasoning.iterations


class ObjectiveController:
    """Drives a reasoning loop toward a typed objective."""

    def __init__(self, loop: ReasoningLoop) -> None:
        self._loop = loop

    def pursue(
        self,
        world_model: WorldModel,
        objective: Objective,
        *,
        budget: TokenBudget | None = None,
    ) -> ControllerResult:
        if objective.is_satisfied(world_model):
            _log.info("objective already satisfied at entry")
            return ControllerResult(
                objective_met=True,
                reasoning=ReasoningResult(stop_reason="already_satisfied"),
            )

        reasoning = self._loop.run(
            world_model,
            objective.describe(),
            budget=budget,
            stop_when=objective.is_satisfied,
        )
        met = objective.is_satisfied(world_model)
        _log.info(
            "objective pursuit complete",
            met=met,
            stop_reason=reasoning.stop_reason,
            iterations=reasoning.iterations,
        )
        return ControllerResult(objective_met=met, reasoning=reasoning)
