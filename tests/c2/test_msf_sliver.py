"""Real-transport C2 backends (C2/C3): Metasploit RPC + Sliver, and engine wiring.

The RPC/gRPC clients themselves are integration-only; here we drive the backend
and launcher logic against fake clients — the exploit→session→whoami chain, and
the engine's `foothold()` factory, without a network.
"""

from __future__ import annotations

from attack_engine.c2.foothold import FootholdRunner
from attack_engine.c2.msf import (
    MSF_SESSION_KEY,
    MsfFootholdLauncher,
    MsfRpcBackend,
)
from attack_engine.c2.session import Session, SessionKind, SessionManager
from attack_engine.c2.sliver import SLIVER_SESSION_KEY, SliverC2Backend
from attack_engine.governance.audit import AuditLog
from attack_engine.governance.gates import HumanGate, approve_all
from attack_engine.schemas import RulesOfEngagement, Scope


def _scope(*, tier: int = 1) -> Scope:
    return Scope(
        engagement_id="engagement-c2", allowed_cidrs=("10.5.0.0/24",),
        roe=RulesOfEngagement(autonomy_tier=tier,
                              authorized_techniques=frozenset({"establish_foothold"})),
        authorized_by="lead@8pi.ai", signature="signed",
    )


def _session(**md: str) -> Session:
    return Session(id="sess-1", engagement_id="engagement-c2", host="10.5.0.12",
                   opened_at="t", metadata=md)


# --- fakes ----------------------------------------------------------------------


class _FakeMsfClient:
    def __init__(self, *, sid: str | None = "3") -> None:
        self.sid = sid
        self.exploits: list[dict] = []
        self.commands: list[tuple[str, str]] = []
        self.stopped: list[str] = []

    def run_exploit(self, *, module, target, payload, options) -> str | None:
        self.exploits.append({"module": module, "target": target, "payload": payload})
        return self.sid

    def run_shell_command(self, session_id: str, command: str) -> str:
        self.commands.append((session_id, command))
        return {"id": "uid=0(root)", "whoami": "root", "hostname": "metasploitable"}.get(
            command, ""
        )

    def session_alive(self, session_id: str) -> bool:
        return True

    def stop_session(self, session_id: str) -> None:
        self.stopped.append(session_id)


class _FakeSliverClient:
    def __init__(self) -> None:
        self.commands: list[tuple[str, str]] = []
        self.killed: list[str] = []

    def execute(self, session_id: str, command: str) -> str:
        self.commands.append((session_id, command))
        return "root" if command == "whoami" else "out"

    def is_alive(self, session_id: str) -> bool:
        return session_id not in self.killed

    def kill(self, session_id: str) -> None:
        self.killed.append(session_id)


# --- MsfRpcBackend --------------------------------------------------------------


def test_msf_backend_routes_by_session_id() -> None:
    client = _FakeMsfClient()
    backend = MsfRpcBackend(client)
    session = _session(**{MSF_SESSION_KEY: "3"})
    assert backend.alive(session)
    assert backend.run_command(session, "whoami") == "root"
    assert client.commands == [("3", "whoami")]
    backend.close(session)
    assert client.stopped == ["3"]


def test_msf_backend_without_session_id_is_dead() -> None:
    backend = MsfRpcBackend(_FakeMsfClient())
    session = _session()  # no msf_session_id
    assert backend.alive(session) is False
    assert backend.run_command(session, "whoami") == ""


# --- MsfFootholdLauncher: the exploit -> live session -> whoami chain ------------


def _launcher(client) -> tuple[MsfFootholdLauncher, SessionManager, AuditLog]:
    scope = _scope(tier=1)
    audit = AuditLog()
    mgr = SessionManager(scope, audit)
    runner = FootholdRunner(mgr, MsfRpcBackend(client), scope, audit,
                            gate=HumanGate(audit, responder=approve_all()))
    return MsfFootholdLauncher(runner, client), mgr, audit


def test_launch_opens_registers_and_proves_session() -> None:
    client = _FakeMsfClient(sid="7")
    launcher, mgr, audit = _launcher(client)
    fh = launcher.launch("10.5.0.12", module="exploit/unix/misc/distcc_exec",
                         kind=SessionKind.SHELL)
    assert fh is not None and fh.ok
    assert fh.session.metadata[MSF_SESSION_KEY] == "7"  # live msf session registered
    assert fh.proof["whoami"] == "root"  # RCE impact proven via the real session
    assert client.commands  # proof commands ran against the msf session
    assert mgr.sessions(active_only=True)  # session tracked by the manager


def test_launch_returns_none_when_no_session_opens() -> None:
    client = _FakeMsfClient(sid=None)  # exploit ran but opened no session
    launcher, mgr, _ = _launcher(client)
    fh = launcher.launch("10.5.0.12", module="exploit/does/not/land")
    assert fh is None
    assert mgr.sessions() == []  # nothing registered
    assert client.commands == []  # no proof attempted


# --- SliverC2Backend ------------------------------------------------------------


def test_sliver_backend_routes_and_kills() -> None:
    client = _FakeSliverClient()
    backend = SliverC2Backend(client)
    session = _session(**{SLIVER_SESSION_KEY: "impl-9"})
    assert backend.alive(session)
    assert backend.run_command(session, "whoami") == "root"
    backend.close(session)
    assert client.killed == ["impl-9"]
    assert backend.alive(session) is False  # killed implant no longer alive


def test_sliver_backend_drives_foothold_teardown() -> None:
    client = _FakeSliverClient()
    scope = _scope(tier=1)
    audit = AuditLog()
    mgr = SessionManager(scope, audit)
    runner = FootholdRunner(mgr, SliverC2Backend(client), scope, audit,
                            gate=HumanGate(audit, responder=approve_all()))
    fh = runner.establish("10.5.0.12", metadata={SLIVER_SESSION_KEY: "impl-1"})
    assert fh.ok and fh.proof["whoami"] == "root"
    assert runner.teardown() == 1
    assert client.killed == ["impl-1"]  # transport released on teardown
