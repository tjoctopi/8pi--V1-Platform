"""Session + listener registry — the C2 book-keeping (O3).

A :class:`SessionManager` tracks the live sessions an engagement has opened and
the listeners reverse payloads call back to. It is **scope-bound**: a session can
only be registered for an in-scope host (the same boundary the Tool Runner
enforces), and every open/close is audited. Listeners give exploitation a known
LHOST/LPORT so reverse-shell modules can run autonomously (O2 no longer needs an
LHOST hand-fed per finding).

This is book-keeping + governance, not transport — actually reaching a session is
the :class:`~attack_engine.c2.backend.C2Backend`'s job.
"""

from __future__ import annotations

import threading
from enum import Enum

from ..governance.audit import AuditLog
from ..schemas.common import StrictModel, iso_now, new_id
from ..schemas.scope import Scope
from ..toolrunner.scope import Resolver, ScopeEnforcer


class SessionKind(str, Enum):
    SHELL = "shell"              # a plain command shell
    METERPRETER = "meterpreter"  # a Meterpreter session
    BEACON = "beacon"            # a C2 beacon (Sliver/Mythic)


class SessionStatus(str, Enum):
    ACTIVE = "active"
    CLOSED = "closed"


class Listener(StrictModel):
    """A callback endpoint reverse payloads connect to (the C2 handler)."""

    id: str
    host: str          # the LHOST an implant/shell dials back to
    port: int          # the LPORT
    payload: str = "cmd/unix/reverse"
    created_at: str


class Session(StrictModel):
    """A live foothold on an authorized host."""

    id: str
    engagement_id: str
    host: str
    kind: SessionKind = SessionKind.SHELL
    opened_at: str
    status: SessionStatus = SessionStatus.ACTIVE
    listener_id: str | None = None
    #: How the session was obtained (exploit module, technique) — for the record.
    opened_by: str = ""
    metadata: dict[str, str] = {}


class SessionManager:
    """Scope-bound, audited registry of live sessions + listeners for one engagement."""

    def __init__(self, scope: Scope, audit: AuditLog, *, resolver: Resolver | None = None) -> None:
        self._scope = scope
        self._audit = audit
        self._enforcer = ScopeEnforcer(scope, resolver=resolver)
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}
        self._listeners: dict[str, Listener] = {}

    @property
    def engagement_id(self) -> str:
        return self._scope.engagement_id

    # --- listeners ------------------------------------------------------------

    def add_listener(self, host: str, port: int, *, payload: str = "cmd/unix/reverse") -> Listener:
        """Register a reverse-shell listener (the known LHOST/LPORT)."""

        listener = Listener(id=new_id("lsnr"), host=host, port=port, payload=payload,
                            created_at=iso_now())
        with self._lock:
            self._listeners[listener.id] = listener
        self._audit.append(
            engagement_id=self.engagement_id, actor="c2",
            action="c2.listener.add", target=host,
            payload={"listener_id": listener.id, "port": port, "payload": payload},
        )
        return listener

    def default_listener(self) -> Listener | None:
        """The first registered listener, if any — the default reverse callback."""

        with self._lock:
            return next(iter(self._listeners.values()), None)

    # --- sessions -------------------------------------------------------------

    def open_session(
        self, host: str, *, kind: SessionKind = SessionKind.SHELL,
        opened_by: str = "", listener_id: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> Session:
        """Register a live session — refused (audited) if the host is out of scope.

        Scope is enforced here just as at the tool boundary: you cannot hold a
        session on a host the engagement never authorized.
        """

        # Reuse the tool-boundary scope check — raises ScopeViolationError if OOS.
        self._enforcer.check(host)
        session = Session(
            id=new_id("sess"), engagement_id=self.engagement_id, host=host, kind=kind,
            opened_at=iso_now(), opened_by=opened_by, listener_id=listener_id,
            metadata=metadata or {},
        )
        with self._lock:
            self._sessions[session.id] = session
        self._audit.append(
            engagement_id=self.engagement_id, actor="c2",
            action="c2.session.opened", target=host,
            payload={"session_id": session.id, "kind": kind.value, "opened_by": opened_by},
        )
        return session

    def close_session(self, session_id: str) -> Session | None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.status is SessionStatus.CLOSED:
                return session
            closed = session.model_copy(update={"status": SessionStatus.CLOSED})
            self._sessions[session_id] = closed
        self._audit.append(
            engagement_id=self.engagement_id, actor="c2",
            action="c2.session.closed", target=closed.host,
            payload={"session_id": session_id},
        )
        return closed

    def get(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def sessions(self, *, active_only: bool = False) -> list[Session]:
        with self._lock:
            values = list(self._sessions.values())
        if active_only:
            return [s for s in values if s.status is SessionStatus.ACTIVE]
        return values

    def close_all(self) -> int:
        """Tear down every active session (engagement teardown / kill switch)."""

        active = self.sessions(active_only=True)
        for s in active:
            self.close_session(s.id)
        return len(active)
