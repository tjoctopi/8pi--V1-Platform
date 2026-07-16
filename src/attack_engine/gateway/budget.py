"""Per-engagement token budget for the model gateway.

A real reasoning loop can spend without bound; the budget is the ceiling the
engagement authorized. The gateway checks it *before* a call (refusing once
exhausted) and charges it *after* a successful one, so a long autonomous
campaign can never silently overrun its cost envelope. Enforcement is
deterministic — an agent cannot raise its own ceiling (mirrors the scope /
rate-limit discipline of the Tool Runner boundary).
"""

from __future__ import annotations

from ..errors import BudgetExceededError
from .types import Usage


class TokenBudget:
    """Mutable token counter with an optional hard ceiling.

    ``max_total_tokens=None`` means unlimited (the ceiling is opt-in). Counters
    are cumulative across every call charged to this budget instance, so one
    budget shared by a whole agent fleet caps the engagement as a whole.
    """

    def __init__(self, max_total_tokens: int | None = None) -> None:
        if max_total_tokens is not None and max_total_tokens < 0:
            raise ValueError("max_total_tokens must be non-negative or None")
        self.max_total_tokens = max_total_tokens
        self.prompt_tokens = 0
        self.completion_tokens = 0

    @property
    def spent(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def remaining(self) -> int | None:
        """Tokens left, or ``None`` when unlimited."""

        if self.max_total_tokens is None:
            return None
        return max(0, self.max_total_tokens - self.spent)

    def ensure_available(self) -> None:
        """Raise :class:`BudgetExceededError` if the ceiling is already reached."""

        if self.max_total_tokens is not None and self.spent >= self.max_total_tokens:
            raise BudgetExceededError(spent=self.spent, limit=self.max_total_tokens)

    def charge(self, usage: Usage) -> None:
        """Record the cost of a completed call."""

        self.prompt_tokens += usage.prompt_tokens
        self.completion_tokens += usage.completion_tokens
