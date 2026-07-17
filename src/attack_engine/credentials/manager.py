"""Credential manager — the governed capture → crack → own lifecycle (Phase E3).

This is the orchestration seam that turns an identity *lead* into identity *power*
and folds it back into planning:

    capture(material)  →  crack(candidates)  →  own(principal)  →  new paths

- **capture** stashes raw material in the :class:`CredentialVault` (never in the
  model, never in a log) and mints a :class:`Credential` in ``CAPTURED`` state.
- **crack** runs the offline :class:`HashCracker` over the captured material and,
  on success, mints a directly-reusable ``PLAINTEXT`` credential in ``CRACKED``
  state (the roast blob is now a password we can authenticate with).
- **own** records that we now control the principal in the world model's identity
  attack graph — which re-plans the route to Domain Admin: owning a cracked
  service account can open a fresh path (that is the "escalate" of the lifecycle).

Everything is audited on the hash-chained log. Cracking is *offline* (no target
interaction, so no scope hit) but still recorded; the on-wire *reuse* of a
credential (Pass-the-Hash / -Ticket against a host) is a real action that the
execution layer (Phase E4 / :class:`~attack_engine.c2.foothold.FootholdRunner`)
performs under an authorization gate — the manager never touches the wire.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..governance.audit import AuditLog
from ..knowledge.worldmodel import WorldModel
from ..logging import get_logger
from ..schemas.credentials import Credential, CredentialState, SecretKind
from .cracker import CrackResult, HashCracker
from .vault import CredentialVault, mask

_log = get_logger("credentials.manager")

#: Roast kinds must be cracked before they can be reused.
_ROAST_KINDS = frozenset({SecretKind.KERBEROS_TGS, SecretKind.KERBEROS_ASREP})


class CredentialManager:
    """Governed credential lifecycle over a vault + offline cracker."""

    def __init__(
        self,
        engagement_id: str,
        audit: AuditLog,
        *,
        vault: CredentialVault | None = None,
        cracker: HashCracker | None = None,
        actor: str = "credentials",
    ) -> None:
        self._engagement_id = engagement_id
        self._audit = audit
        self._vault = vault or CredentialVault()
        self._cracker = cracker or HashCracker()
        self._actor = actor
        self._creds: dict[str, Credential] = {}

    @property
    def vault(self) -> CredentialVault:
        return self._vault

    def credentials(self) -> list[Credential]:
        """All credentials captured/minted this engagement."""

        return list(self._creds.values())

    def capture(
        self,
        principal: str,
        kind: SecretKind,
        material: str,
        *,
        source: str = "unknown",
        domain: str | None = None,
        confidence: float = 1.0,
    ) -> Credential:
        """Store captured secret material in the vault and mint a Credential.

        The raw ``material`` goes to the vault; the returned model carries only an
        opaque ref and a masked preview. Audited — the payload never holds material.
        """

        ref = self._vault.put(material)
        cred = Credential(
            engagement_id=self._engagement_id,
            principal=principal,
            kind=kind,
            state=CredentialState.CAPTURED,
            source=source,
            domain=domain,
            secret_ref=ref,
            masked=mask(material),
            confidence=confidence,
        )
        self._creds[cred.id] = cred
        self._audit.append(
            engagement_id=self._engagement_id, actor=self._actor,
            action="credential.captured", target=principal,
            payload={"credential_id": cred.id, "kind": kind.value, "source": source,
                     "domain": domain, "masked": cred.masked},
        )
        _log.info("credential captured", principal=principal, kind=kind.value, source=source)
        return cred

    def crack(self, credential: Credential, wordlist: Iterable[str]) -> Credential | None:
        """Crack captured material offline; on success mint a PLAINTEXT credential.

        Returns the new ``CRACKED`` plaintext credential, or ``None`` if the
        wordlist did not recover the secret. Both outcomes are audited (with the
        candidate count, never the plaintext).
        """

        material = self._vault.get(credential.secret_ref)
        result = self._run_crack(credential.kind, material, wordlist)
        if not result.cracked or result.plaintext is None:
            self._audit.append(
                engagement_id=self._engagement_id, actor=self._actor,
                action="credential.crack.failed", target=credential.principal,
                payload={"credential_id": credential.id, "kind": credential.kind.value,
                         "tried": result.tried},
            )
            _log.info("crack failed", principal=credential.principal, tried=result.tried)
            return None

        ref = self._vault.put(result.plaintext)
        cracked = Credential(
            engagement_id=self._engagement_id,
            principal=credential.principal,
            kind=SecretKind.PLAINTEXT,
            state=CredentialState.CRACKED,
            source="cracked",
            domain=credential.domain,
            secret_ref=ref,
            masked=mask(result.plaintext),
            confidence=1.0,  # a verified crack authenticates deterministically
        )
        self._creds[cracked.id] = cracked
        self._audit.append(
            engagement_id=self._engagement_id, actor=self._actor,
            action="credential.cracked", target=credential.principal,
            payload={"credential_id": cracked.id, "from": credential.id,
                     "kind": credential.kind.value, "tried": result.tried,
                     "masked": cracked.masked},
        )
        _log.info("credential cracked", principal=credential.principal, tried=result.tried)
        return cracked

    def own(self, credential: Credential, world_model: WorldModel) -> bool:
        """Record that we now control ``credential.principal`` — re-plans the AD graph.

        Owning a principal is what makes the credential *actionable* in path
        planning: :meth:`WorldModel.domain_admin_paths` recomputes from the owned
        set, so a cracked service account can surface a fresh route to Domain
        Admin. Only directly-reusable credentials own a principal (a roast blob
        must be cracked first). Returns whether the principal was newly owned.
        """

        if not credential.is_reusable:
            _log.info("credential not reusable — crack before owning",
                      principal=credential.principal, kind=credential.kind.value)
            return False
        already = credential.principal.strip().upper() in {
            p.strip().upper() for p in world_model.owned_principals
        }
        world_model.mark_owned(credential.principal)
        self._audit.append(
            engagement_id=self._engagement_id, actor=self._actor,
            action="credential.owned", target=credential.principal,
            payload={"credential_id": credential.id, "kind": credential.kind.value,
                     "newly_owned": not already},
        )
        _log.info("principal owned", principal=credential.principal, newly_owned=not already)
        return not already

    def _run_crack(
        self, kind: SecretKind, material: str, wordlist: Iterable[str]
    ) -> CrackResult:
        if kind in _ROAST_KINDS:
            return self._cracker.crack_kerberos(material, wordlist)
        if kind is SecretKind.NT_HASH:
            return self._cracker.crack_nt(material, wordlist)
        # Plaintext / key / ticket are already usable — nothing to crack.
        return CrackResult(cracked=False, tried=0)
