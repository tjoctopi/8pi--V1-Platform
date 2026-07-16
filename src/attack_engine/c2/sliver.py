"""Sliver C2 backend (O3, real transport) — modern beacon/session operations.

Sliver is the recommended primary C2: a persistent server holds implant sessions
and beacons, and the engine drives them through the same
:class:`~attack_engine.c2.backend.C2Backend` contract as Metasploit — so the rest
of the platform is backend-agnostic.

    * :class:`SliverClient` — the tiny operator surface we use (Protocol). The
      real :class:`SliverGrpcClient` implements it via ``sliver-py`` and is the
      only integration-only, network-touching code (never hit by the suite).
    * :class:`SliverC2Backend` — a ``C2Backend`` routing to an implant by its
      ``sliver_id`` (carried in ``Session.metadata``).

Governance is unchanged: the FootholdRunner/PostExOperator that use this backend
authorise, scope-check, audit, and can tear the session down.
"""

from __future__ import annotations

import contextlib
from typing import Protocol, runtime_checkable

from .session import Session

#: Where the Sliver session/beacon id is stashed on a registered Session.
SLIVER_SESSION_KEY = "sliver_id"


@runtime_checkable
class SliverClient(Protocol):
    """The subset of the Sliver operator API the engine uses."""

    def execute(self, session_id: str, command: str) -> str:
        """Run one command on an implant session and return its (bounded) output."""
        ...

    def is_alive(self, session_id: str) -> bool: ...

    def kill(self, session_id: str) -> None: ...


class SliverC2Backend:
    """A :class:`C2Backend` over a Sliver server, routed by ``sliver_id``."""

    def __init__(self, client: SliverClient) -> None:
        self._client = client

    @staticmethod
    def _sid(session: Session) -> str | None:
        return session.metadata.get(SLIVER_SESSION_KEY)

    def alive(self, session: Session) -> bool:
        sid = self._sid(session)
        return self._client.is_alive(sid) if sid else False

    def run_command(self, session: Session, command: str) -> str:
        sid = self._sid(session)
        return self._client.execute(sid, command) if sid else ""

    def close(self, session: Session) -> None:
        sid = self._sid(session)
        if sid:
            self._client.kill(sid)


class SliverGrpcClient:  # pragma: no cover - integration-only, network transport
    """Real :class:`SliverClient` over ``sliver-py`` gRPC. Never hit by the suite.

    Constructed from an operator config file. Import is lazy so the dependency is
    only needed where a real Sliver server is deployed.
    """

    def __init__(self, config_path: str) -> None:
        from sliver import SliverClient as _Client
        from sliver import SliverClientConfig

        self._config = SliverClientConfig.parse_config_file(config_path)
        self._client = _Client(self._config)

    def execute(self, session_id: str, command: str) -> str:
        interact = self._client.interact_session(session_id)
        parts = command.split()
        result = interact.execute(parts[0], parts[1:], True)
        return (result.Stdout or b"").decode("utf-8", "replace")

    def is_alive(self, session_id: str) -> bool:
        return session_id in {s.ID for s in self._client.sessions()}

    def kill(self, session_id: str) -> None:
        with contextlib.suppress(Exception):
            self._client.interact_session(session_id).kill()
