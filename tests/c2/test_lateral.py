"""Lateral movement (E4): credential reuse (PtH/PtT) → proven, governed session.

The real impacket exec client is integration-only; here we drive the backend and
launcher against a fake client — the credential-reuse → session → whoami chain,
its governance (technique-tagged authorization, gate, teardown), and the escalate
loop (a landed session keeps the owned set coherent), without a network.
"""

from __future__ import annotations

from attack_engine.c2.foothold import FootholdRunner
from attack_engine.c2.lateral import (
    LATERAL_HANDLE_KEY,
    LateralBackend,
    LateralMovementLauncher,
    LateralProtocol,
)
from attack_engine.c2.session import Session, SessionManager
from attack_engine.credentials.vault import CredentialVault
from attack_engine.governance.audit import AuditLog
from attack_engine.governance.gates import HumanGate, approve_all, deny_all
from attack_engine.knowledge.worldmodel import WorldModel
from attack_engine.schemas import RulesOfEngagement, Scope
from attack_engine.schemas.credentials import Credential, CredentialState, SecretKind

_PROOF = {"id": "uid=500(svc_sql)", "whoami": "corp\\svc_sql", "hostname": "DB01"}


def _scope(*, tier: int = 1) -> Scope:
    return Scope(
        engagement_id="engagement-e4", allowed_cidrs=("10.5.0.0/24",),
        roe=RulesOfEngagement(autonomy_tier=tier,
                              authorized_techniques=frozenset({"establish_foothold"})),
        authorized_by="lead@8pi.ai", signature="signed",
    )


def _session(**md: str) -> Session:
    return Session(id="sess-1", engagement_id="engagement-e4", host="10.5.0.30",
                   opened_at="t", metadata=md)


class _FakeLateralClient:
    """Records auth + exec; returns canned proof output for a landed session."""

    def __init__(self, *, auth_ok: bool = True) -> None:
        self._auth_ok = auth_ok
        self.opened: list[dict[str, str | None]] = []
        self.commands: list[tuple[str, str]] = []
        self.closed: list[str] = []
        self._live: set[str] = set()

    def open(self, *, host, protocol, principal, domain, secret_kind, secret) -> str | None:
        self.opened.append({"host": host, "protocol": protocol, "principal": principal,
                            "domain": domain, "secret_kind": secret_kind, "secret": secret})
        if not self._auth_ok:
            return None
        handle = f"lat-{len(self.opened)}"
        self._live.add(handle)
        return handle

    def run(self, handle: str, command: str) -> str:
        self.commands.append((handle, command))
        return _PROOF.get(command, "")

    def alive(self, handle: str) -> bool:
        return handle in self._live

    def close(self, handle: str) -> None:
        self.closed.append(handle)
        self._live.discard(handle)


def _cred(vault: CredentialVault, *, kind: SecretKind = SecretKind.NT_HASH,
          material: str = "41aed72cec76816423703d8e545eea31") -> Credential:
    return Credential(
        engagement_id="engagement-e4", principal="svc_sql@CORP.LOCAL", kind=kind,
        state=CredentialState.CRACKED, source="cracked", domain="CORP.LOCAL",
        secret_ref=vault.put(material), masked="41a…****",
    )


def _launcher(client, *, responder=approve_all(), kill=None, tier=1):
    scope = _scope(tier=tier)
    audit = AuditLog()
    mgr = SessionManager(scope, audit)
    runner = FootholdRunner(mgr, LateralBackend(client), scope, audit,
                            gate=HumanGate(audit, responder=responder), kill_switch=kill)
    vault = CredentialVault()
    return LateralMovementLauncher(runner, client, vault), mgr, audit, vault


# --- LateralBackend routing -----------------------------------------------------


def test_backend_routes_by_handle() -> None:
    client = _FakeLateralClient()
    client._live.add("h1")
    backend = LateralBackend(client)
    session = _session(**{LATERAL_HANDLE_KEY: "h1"})
    assert backend.alive(session)
    assert backend.run_command(session, "whoami") == "corp\\svc_sql"
    backend.close(session)
    assert client.closed == ["h1"]


def test_backend_without_handle_is_dead() -> None:
    backend = LateralBackend(_FakeLateralClient())
    session = _session()  # no lateral_handle
    assert backend.alive(session) is False
    assert backend.run_command(session, "whoami") == ""


# --- the credential-reuse -> session -> whoami chain ----------------------------


def test_move_lands_registers_and_proves_session() -> None:
    client = _FakeLateralClient()
    launcher, mgr, audit, vault = _launcher(client)
    cred = _cred(vault)

    fh = launcher.move("10.5.0.30", cred, protocol=LateralProtocol.WMIEXEC)

    assert fh is not None and fh.ok
    assert fh.session.metadata[LATERAL_HANDLE_KEY] == "lat-1"
    assert fh.session.metadata["principal"] == "svc_sql@CORP.LOCAL"
    assert fh.proof["whoami"] == "corp\\svc_sql"  # proven over the lateral channel
    assert mgr.sessions(active_only=True)          # tracked by the manager
    # The secret reached the client in-memory, and only as the NT hash.
    assert client.opened[0]["secret"] == "41aed72cec76816423703d8e545eea31"
    assert client.opened[0]["protocol"] == "wmiexec"


def test_move_audits_pass_the_hash_technique_and_never_the_secret() -> None:
    client = _FakeLateralClient()
    launcher, _, audit, vault = _launcher(client)
    launcher.move("10.5.0.30", _cred(vault))

    entries = audit.entries("engagement-e4")
    authz = [e for e in entries if e.action == "action.authorized"]
    assert authz and authz[0].payload["technique"] == "T1550.002"  # Pass the Hash
    # No secret material anywhere in the audit trail.
    assert all("41aed72cec76816423703d8e545eea31" not in str(e.payload) for e in entries)


def test_ptt_credential_tagged_pass_the_ticket() -> None:
    client = _FakeLateralClient()
    launcher, _, audit, vault = _launcher(client)
    cred = _cred(vault, kind=SecretKind.TICKET, material="TGT-blob")
    launcher.move("10.5.0.30", cred)
    authz = [e for e in audit.entries("engagement-e4") if e.action == "action.authorized"]
    assert authz[0].payload["technique"] == "T1550.003"  # Pass the Ticket


def test_move_refuses_uncracked_roast_blob() -> None:
    client = _FakeLateralClient()
    launcher, mgr, _, vault = _launcher(client)
    roast = _cred(vault, kind=SecretKind.KERBEROS_TGS, material="$krb5tgs$...")
    assert launcher.move("10.5.0.30", roast) is None
    assert client.opened == []          # never dialed the host
    assert mgr.sessions() == []


def test_move_returns_none_when_auth_fails() -> None:
    client = _FakeLateralClient(auth_ok=False)
    launcher, mgr, _, vault = _launcher(client)
    assert launcher.move("10.5.0.30", _cred(vault)) is None
    assert mgr.sessions() == []         # nothing registered
    assert client.commands == []        # no proof attempted


def test_move_denied_by_gate_opens_no_session() -> None:
    client = _FakeLateralClient()
    launcher, mgr, audit, vault = _launcher(client, responder=deny_all, tier=0)
    assert launcher.move("10.5.0.30", _cred(vault)) is None
    assert mgr.sessions() == []
    assert any(e.action == "c2.foothold.denied" for e in audit.entries("engagement-e4"))


def test_teardown_closes_lateral_channel() -> None:
    client = _FakeLateralClient()
    launcher, mgr, _, vault = _launcher(client)
    fh = launcher.move("10.5.0.30", _cred(vault))
    assert fh is not None
    launcher._runner.teardown()
    assert client.closed == ["lat-1"]                       # transport released
    assert mgr.sessions(active_only=True) == []             # bookkeeping closed


# --- the escalate loop: a landed session keeps the owned set coherent -----------


def test_move_marks_principal_owned_for_replanning() -> None:
    client = _FakeLateralClient()
    launcher, _, _, vault = _launcher(client)
    wm = WorldModel("engagement-e4")
    launcher.move("10.5.0.30", _cred(vault), world_model=wm)
    assert "SVC_SQL@CORP.LOCAL" in wm.owned_principals
