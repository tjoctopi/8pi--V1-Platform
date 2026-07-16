"""Model gateway data types (provider-agnostic)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from ..schemas.common import StrictModel

Role = Literal["system", "user", "assistant", "tool"]


class ChatMessage(StrictModel):
    role: Role
    content: str

    @classmethod
    def system(cls, content: str) -> ChatMessage:
        return cls(role="system", content=content)

    @classmethod
    def user(cls, content: str) -> ChatMessage:
        return cls(role="user", content=content)

    @classmethod
    def assistant(cls, content: str) -> ChatMessage:
        """A prior model turn — used to replay a bad reply during a retry."""

        return cls(role="assistant", content=content)

    @classmethod
    def tool(cls, content: str) -> ChatMessage:
        """A tool-result turn fed back to the model (multi-turn reasoning)."""

        return cls(role="tool", content=content)

    def to_dict(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


class Usage(StrictModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class ModelResponse(StrictModel):
    """Normalised completion result across all providers."""

    text: str
    model: str
    tier: str
    usage: Usage = Field(default_factory=Usage)
    finish_reason: str | None = None
    provider: str = "unknown"
    #: Extra provider-specific data (never required by callers).
    extra: dict[str, Any] = Field(default_factory=dict)
