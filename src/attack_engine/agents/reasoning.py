"""The reasoning loop — Perceive → Plan → Act → Observe → Reflect (spec §2).

This is the brain the fixed 8-phase orchestrator lacked: instead of running a
scripted sequence, an agent *perceives* the world model, *plans* a next action
from it, *acts* through the Tool Runner boundary, *observes* the result back into
the world model, and *reflects* on whether to continue — adapting each step to
what it just learned.

The loop is deliberately decoupled from any concrete capability. Its four
collaborators are Protocols:

    * :class:`Planner`  — proposes ranked actions (LLM-backed by default).
    * :class:`Actor`    — executes one action (a Tool Runner call, in practice).
    * :class:`Observer` — folds the outcome into the world model as beliefs.
    * :class:`Reflector`— decides continue / stop / stuck.

so a specialist (Recon, Web, …) supplies its own Actor/Observer while reusing the
loop, and the whole thing is unit-testable with fakes and a mock model. The
Planner proposes; deterministic oracles (elsewhere) confirm — the loop never
promotes a belief to truth (rule #1).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Protocol

from ..errors import AttackEngineError, BudgetExceededError
from ..gateway.budget import TokenBudget
from ..gateway.router import ModelGateway
from ..gateway.types import ChatMessage
from ..knowledge.worldmodel import WorldModel
from ..logging import get_logger
from ..schemas.agentspec import ModelTier
from .actions import (
    FINISH_TOOL,
    ActionOutcome,
    ActionPlan,
    ProposedAction,
    ReasoningResult,
    ReasoningStep,
    StepDecision,
)

_log = get_logger("agent.reasoning")


class LoopContext:
    """The read-only view of the world handed to each stage every step.

    Carries the shared belief state, the objective in plain language, the trace
    so far, the current step index, and the (optional) token budget — everything
    a stage needs to make an adaptive decision.
    """

    def __init__(
        self,
        world_model: WorldModel,
        objective: str,
        history: tuple[ReasoningStep, ...],
        step: int,
        budget: TokenBudget | None,
    ) -> None:
        self.world_model = world_model
        self.objective = objective
        self.history = history
        self.step = step
        self.budget = budget


class Planner(Protocol):
    def propose(self, ctx: LoopContext) -> ActionPlan: ...


class Actor(Protocol):
    def act(self, action: ProposedAction) -> ActionOutcome: ...


class Observer(Protocol):
    def observe(self, action: ProposedAction, outcome: ActionOutcome, ctx: LoopContext) -> None: ...


class Reflector(Protocol):
    def reflect(
        self, action: ProposedAction, outcome: ActionOutcome, ctx: LoopContext
    ) -> StepDecision: ...


class HeuristicReflector:
    """Default Reflector: stop after ``max_no_progress`` unproductive steps.

    "Progress" is simply whether the action's outcome was ``ok``. It resets the
    streak on any productive step, so a run only gives up when it has genuinely
    stalled — the deterministic backstop under any LLM-driven planning.
    """

    def __init__(self, max_no_progress: int = 3) -> None:
        self._max_no_progress = max_no_progress
        self._streak = 0

    def reflect(
        self, action: ProposedAction, outcome: ActionOutcome, ctx: LoopContext
    ) -> StepDecision:
        if outcome.ok:
            self._streak = 0
            return StepDecision.CONTINUE
        self._streak += 1
        if self._streak >= self._max_no_progress:
            return StepDecision.STUCK
        return StepDecision.CONTINUE


class ReasoningLoop:
    """Runs the Perceive→Plan→Act→Observe→Reflect cycle toward an objective."""

    def __init__(
        self,
        planner: Planner,
        actor: Actor,
        observer: Observer,
        reflector: Reflector | None = None,
        *,
        max_steps: int = 20,
        max_per_tool: int = 3,
    ) -> None:
        self._planner = planner
        self._actor = actor
        self._observer = observer
        self._reflector = reflector or HeuristicReflector()
        self._max_steps = max_steps
        #: Cap on successful runs of any single tool, so the loop diversifies across
        #: the tool set rather than fixating on one scanner.
        self._max_per_tool = max_per_tool

    def run(
        self,
        world_model: WorldModel,
        objective: str,
        *,
        budget: TokenBudget | None = None,
        stop_when: Callable[[WorldModel], bool] | None = None,
    ) -> ReasoningResult:
        """Run the loop toward ``objective`` until a stop condition trips.

        ``stop_when`` (used by the objective controller) is evaluated against the
        world model before each step; when it returns True the loop finishes with
        reason ``objective_satisfied`` — including immediately, at step 0.
        """

        result = ReasoningResult(stop_reason="max_steps")
        # Signatures of actions already run successfully — so the loop never wastes a
        # step re-running the identical tool call (e.g. crawling the same host twice)
        # and instead progresses through the remaining tools. A call with different
        # params/target (a genuinely new probe) has a different signature and is allowed.
        done: set[tuple[str, str, str]] = set()
        # How many times each tool has run successfully — a cap stops the planner
        # fixating on one broad scanner (e.g. re-running nuclei with tweaked params
        # for many steps) and forces it to move through the rest of the tool set.
        tool_runs: dict[str, int] = {}
        for step in range(self._max_steps):
            if stop_when is not None and stop_when(world_model):
                result.stop_reason = "objective_satisfied"
                break
            if budget is not None:
                try:
                    budget.ensure_available()
                except BudgetExceededError:
                    result.stop_reason = "budget_exhausted"
                    break

            ctx = LoopContext(world_model, objective, tuple(result.steps), step, budget)

            # Plan — the LLM boundary. A failed/invalid plan (bad model output,
            # transient gateway error) degrades this phase gracefully rather than
            # crashing the whole loop/campaign (same posture as the Actor's guard).
            try:
                plan = self._planner.propose(ctx)
                action = self._select(plan, done, tool_runs, self._max_per_tool)
            except BudgetExceededError:
                result.stop_reason = "budget_exhausted"
                break
            except AttackEngineError as exc:
                _log.warning("planner failed; degrading phase", error=str(exc), step=step)
                result.stop_reason = "planner_error"
                break
            if action is None or action.tool == FINISH_TOOL:
                # Either the planner chose to finish, or every proposed action has
                # already been run — nothing new left to try, so stop cleanly.
                result.stop_reason = "planner_finished" if (
                    action is not None or not plan.actions
                ) else "exhausted"
                break

            # Act → Observe → Reflect
            outcome = self._actor.act(action)
            if outcome.ok:
                done.add(self._sig(action))
                tool_runs[action.tool] = tool_runs.get(action.tool, 0) + 1
            self._observer.observe(action, outcome, ctx)
            decision = self._reflector.reflect(action, outcome, ctx)
            result.steps.append(
                ReasoningStep(
                    index=step,
                    action=action,
                    ok=outcome.ok,
                    outcome_summary=outcome.summary,
                    decision=decision,
                )
            )
            # INFO, not DEBUG: an autonomous loop that plans + acts silently is
            # indistinguishable from one that is stuck. Each step (which tool ran,
            # on what, whether it succeeded, and the reflector's decision) is the
            # operator's window into the run — and mirrors the SSE the console shows.
            _log.info(
                "reasoning step",
                step=step,
                tool=action.tool,
                target=action.target,
                ok=outcome.ok,
                summary=(outcome.summary or "")[:160],
                decision=decision.value,
            )
            if decision is StepDecision.STOP:
                result.stop_reason = "reflector_stop"
                break
            if decision is StepDecision.STUCK:
                result.stop_reason = "stuck"
                break
        return result

    @staticmethod
    def _sig(action: ProposedAction) -> tuple[str, str, str]:
        """A stable identity for an action — same tool + target + params ⇒ same run."""

        params = ", ".join(f"{k}={action.params[k]!r}" for k in sorted(action.params))
        return (action.tool, action.target or "", params)

    @classmethod
    def _select(
        cls,
        plan: ActionPlan,
        done: set[tuple[str, str, str]] | None = None,
        tool_runs: dict[str, int] | None = None,
        max_per_tool: int = 3,
    ) -> ProposedAction | None:
        """Highest expected-value action, skipping ones already run this loop.

        Two filters force the loop to progress instead of spinning: exact repeats
        (same tool + target + params) are skipped, and a tool that has already run
        ``max_per_tool`` times is skipped so the planner can't fixate on one scanner
        (e.g. re-running nuclei with tweaked params). An explicit FINISH always wins.
        Returns ``None`` when nothing new/allowed remains (loop stops "exhausted").
        """

        if not plan.actions:
            return None
        done = done or set()
        tool_runs = tool_runs or {}
        finish = [a for a in plan.actions if a.tool == FINISH_TOOL]
        if finish:
            return max(finish, key=lambda a: a.expected_value)
        fresh = [
            a for a in plan.actions
            if cls._sig(a) not in done
            and tool_runs.get(a.tool, 0) < max_per_tool
        ]
        if not fresh:
            return None
        return max(fresh, key=lambda a: a.expected_value)


class LlmPlanner:
    """A Planner that asks a model for a ranked :class:`ActionPlan`.

    Provider-agnostic (rule #4): it assembles the world-model state into a prompt
    and uses ``gateway.respond_json`` so the reply is schema-validated — the model
    emits a structured action set, not prose we parse by hand. Token spend flows
    through the loop's shared budget via ``ctx.budget``.
    """

    def __init__(
        self,
        gateway: ModelGateway,
        *,
        tools: Sequence[str],
        system_prompt: str,
        tier: ModelTier = ModelTier.FRONTIER,
        actor_name: str = "planner",
        engagement_id: str | None = None,
    ) -> None:
        self._gateway = gateway
        self._tools = list(tools)
        self._system_prompt = system_prompt
        self._tier = tier
        self._actor_name = actor_name
        self._engagement_id = engagement_id

    def propose(self, ctx: LoopContext) -> ActionPlan:
        return self._gateway.respond_json(
            self._messages(ctx),
            ActionPlan,
            tier=self._tier,
            engagement_id=self._engagement_id,
            actor=self._actor_name,
            budget=ctx.budget,
        )

    def _messages(self, ctx: LoopContext) -> list[ChatMessage]:
        wm = ctx.world_model
        leads = wm.open_hypotheses(limit=8)
        assets = wm.reachable_assets()

        lead_lines = "\n".join(
            f"- [{h.confidence:.2f}] {h.kind} on {h.subject}: {h.title}" for h in leads
        ) or "(none yet)"
        asset_lines = "\n".join(
            f"- {a.address} ({len(a.services)} services)" for a in assets
        ) or "(none discovered yet)"
        recent = "\n".join(
            f"- step {s.index}: {s.action.tool} -> {'ok' if s.ok else 'no result'}"
            for s in ctx.history[-5:]
        ) or "(nothing yet)"

        state = (
            f"OBJECTIVE: {ctx.objective}\n\n"
            f"REACHABLE ASSETS:\n{asset_lines}\n\n"
            f"OPEN LEADS (confidence):\n{lead_lines}\n\n"
            f"RECENT STEPS:\n{recent}\n\n"
            f"AVAILABLE TOOLS: {', '.join(self._tools)}\n"
            f"(Use tool '{FINISH_TOOL}' when the objective is met or no useful "
            "action remains.)\n\n"
            "Propose the ranked next actions. Prefer the cheapest action that "
            "most reduces uncertainty toward the objective."
        )
        return [
            ChatMessage.system(self._system_prompt),
            ChatMessage.user(state),
        ]
