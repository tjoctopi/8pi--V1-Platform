"""Tool Runner data contracts.

``ToolResult`` is the full-fidelity record of one tool invocation: the raw
bytes (logged immutably), the structured parse, timing, and the audit id that
ties it into the hash chain. A ``ToolProfile`` is the *validated* description
of how to run a tool — agents pass a profile, never a raw command line, so the
Tool Runner controls the actual argv.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field, field_validator

from .common import StrictModel, iso_now


class ToolProfile(StrictModel):
    """How an agent asks for a tool to run — declarative, no shell strings.

    ``mutating`` marks profiles that change target state; the Tool Runner
    refuses these when the engagement RoE is read-only. Arguments are a typed
    mapping the wrapper translates into a safe argv; agents can never inject a
    raw command line.
    """

    #: Named preset within the wrapper (e.g. "quick", "full", "confirm").
    preset: str = "default"
    #: Structured, wrapper-interpreted arguments (never a raw command string).
    args: dict[str, Any] = Field(default_factory=dict)
    #: Marks a profile that mutates target state (blocked under read-only RoE).
    mutating: bool = False
    timeout_sec: int | None = Field(default=None, ge=1, le=86400)

    @field_validator("args")
    @classmethod
    def _no_shell_metachars_in_str_values(cls, args: dict[str, Any]) -> dict[str, Any]:
        # Defence in depth: even though wrappers build argv lists (no shell),
        # reject obviously dangerous string values early so they never reach a
        # wrapper by mistake.
        forbidden = set(";|&`$><\n\r")
        for key, val in args.items():
            if isinstance(val, str) and forbidden & set(val):
                raise ValueError(
                    f"argument {key!r} contains shell metacharacters: {val!r}"
                )
        return args


class ToolResult(StrictModel):
    """Full-fidelity outcome of one tool invocation (rule #2 boundary output).

    ``raw`` is the untouched tool output, logged immutably into the audit
    chain. ``parsed`` is the wrapper's structured interpretation that agents
    and oracles consume. ``audit_id`` links this result to its audit entry.
    """

    tool: str
    target: str
    preset: str = "default"
    raw: bytes
    parsed: dict[str, Any]
    exit_code: int
    started_at: str = Field(default_factory=iso_now)
    ended_at: str = Field(default_factory=iso_now)
    audit_id: str
    engagement_id: str
    #: Sandbox backend that executed it (docker/local/noop) — audited.
    sandbox: str = "unknown"

    @property
    def ok(self) -> bool:
        return self.exit_code == 0
