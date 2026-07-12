"""C2 transport backend — how a post-ex command actually reaches a session (O3).

The engine's post-exploitation layer is backend-agnostic: it speaks to a live
session through this small protocol, so the concrete C2 (Metasploit RPC, Sliver,
Mythic) is a swappable implementation. A persistent C2 server holds sessions
across calls — that is the backend's concern, not the rest of the engine's.

Shipped here: the protocol + an in-memory :class:`MockC2Backend` for tests and
dry-runs. Real backends (msfrpcd / sliver-client) plug in behind the same
interface and are wired when the persistent C2 server is deployed.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .session import Session


@runtime_checkable
class C2Backend(Protocol):
    """Minimal transport to a live session."""

    def alive(self, session: Session) -> bool:
        """Whether the session is still reachable."""
        ...

    def run_command(self, session: Session, command: str) -> str:
        """Run one command on the session and return its (bounded) output."""
        ...


class MockC2Backend:
    """In-memory backend for tests/dry-runs — canned per-command output.

    Commands with no canned entry fall back to ``default`` (or empty). Records
    every command it was asked to run so tests can assert on post-ex behaviour
    without a real C2 server.
    """

    def __init__(self, responses: dict[str, str] | None = None, *, alive: bool = True) -> None:
        self._responses = responses or {}
        self._alive = alive
        self.commands: list[tuple[str, str]] = []  # (session_id, command)

    def alive(self, session: Session) -> bool:
        return self._alive

    def run_command(self, session: Session, command: str) -> str:
        self.commands.append((session.id, command))
        if command in self._responses:
            return self._responses[command]
        return self._responses.get("default", "")
