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

    def close(self, session: Session) -> None:
        """Tear down the underlying transport for ``session`` (kill-switch/teardown).

        Idempotent; safe to call on an already-dead session. Bookkeeping (marking
        the Session CLOSED) is the SessionManager's job — this releases the real
        channel (an msfrpc session, a Sliver beacon handle).
        """
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
        self.closed: list[str] = []  # session ids torn down

    def alive(self, session: Session) -> bool:
        return self._alive and session.id not in self.closed

    def run_command(self, session: Session, command: str) -> str:
        self.commands.append((session.id, command))
        if command in self._responses:
            return self._responses[command]
        return self._responses.get("default", "")

    def close(self, session: Session) -> None:
        if session.id not in self.closed:
            self.closed.append(session.id)
