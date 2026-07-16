"""Action data models for the reasoning loop (spec §2, the brain).

These are the structured objects the loop passes between its stages. The
LLM-facing ones (:class:`ProposedAction`, :class:`ActionPlan`) are the schema a
Planner returns via ``gateway.respond_json`` — the model proposes *what to try
and why*, never truth (rule #1). The internal records (:class:`ReasoningStep`,
:class:`ReasoningResult`) are the loop's own trace for the audit / SSE narrative.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import Field

from ..schemas.common import StrictModel

#: Pseudo-tool a Planner emits to signal "objective met / nothing useful left".
FINISH_TOOL = "finish"


class ProposedAction(StrictModel):
    """One candidate next step the Planner proposes."""

    tool: str  # a capability/tool name, or FINISH_TOOL to stop
    rationale: str
    target: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    #: How promising this action is toward the objective (0..1); used to rank.
    expected_value: float = Field(default=0.5, ge=0.0, le=1.0)


class ActionPlan(StrictModel):
    """The Planner's ranked proposal set for the current step.

    A list rather than a single action so the loop can rank by expected value
    and so a debate/panel step (later phases) can compare whole plans.
    """

    assessment: str = ""  # the model's one-line read of the current situation
    actions: tuple[ProposedAction, ...] = Field(default_factory=tuple)


class StepDecision(str, Enum):
    """The Reflector's verdict after observing an action's outcome."""

    CONTINUE = "continue"  # keep going
    STOP = "stop"  # clean finish (e.g. objective satisfied)
    STUCK = "stuck"  # no progress; abandon this line of attack


@dataclass(frozen=True)
class ActionOutcome:
    """What an Actor returns after executing a :class:`ProposedAction`."""

    ok: bool
    summary: str
    raw: Any | None = None


@dataclass(frozen=True)
class ReasoningStep:
    """One completed loop iteration, kept for the trace."""

    index: int
    action: ProposedAction
    ok: bool
    outcome_summary: str
    decision: StepDecision


@dataclass
class ReasoningResult:
    """The outcome of a whole reasoning-loop run."""

    steps: list[ReasoningStep] = field(default_factory=list)
    stop_reason: str = "max_steps"

    @property
    def iterations(self) -> int:
        return len(self.steps)
