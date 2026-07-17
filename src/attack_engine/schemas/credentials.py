"""Credential entities — the capture → crack → reuse → escalate lifecycle (Phase E).

A :class:`Credential` is what turns an identity *lead* into identity *power*: a
recovered secret for a principal means the fleet can act **as** that principal,
extending the reachable attack surface (a cracked service account, a DCSync'd NT
hash, a stolen ticket). Like a Finding, a credential carries provenance and
confidence; unlike a Finding it is not a vulnerability but a *capability*.

Data minimization (rule §8): the raw secret is **never** stored in this model —
only an opaque ``secret_ref`` into the credential vault plus a masked preview for
reports. The vault is where material is held (encrypted-at-rest + access-
controlled in production).
"""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from .common import StrictModel, new_id, utcnow


class SecretKind(str, Enum):
    """The form of the recovered secret — decides how it can be reused."""

    PLAINTEXT = "plaintext"          # a password → auth anywhere
    NT_HASH = "nt_hash"              # NTLM hash → Pass-the-Hash (no crack needed)
    AES_KEY = "aes_key"              # Kerberos AES key → Overpass-the-Hash
    TICKET = "ticket"                # TGT/service ticket → Pass-the-Ticket
    KERBEROS_TGS = "kerberos_tgs"    # roasted service ticket → must be CRACKED first
    KERBEROS_ASREP = "kerberos_asrep"  # AS-REP material → must be CRACKED first


class CredentialState(str, Enum):
    CAPTURED = "captured"    # material obtained (hash / roasted ticket)
    CRACKED = "cracked"      # plaintext recovered from captured material
    VALIDATED = "validated"  # confirmed to authenticate against a target


#: Kinds that are usable *as captured* (Pass-the-Hash / -Ticket / Overpass);
#: roast kinds are NOT — they must be cracked to plaintext first.
_REUSABLE_KINDS = frozenset(
    {SecretKind.PLAINTEXT, SecretKind.NT_HASH, SecretKind.AES_KEY, SecretKind.TICKET}
)


class Credential(StrictModel):
    """A recovered secret for a principal — metadata only; material lives in the vault."""

    id: str = Field(default_factory=lambda: new_id("cred"))
    engagement_id: str
    principal: str                    # who it authenticates as (user@domain / host$)
    kind: SecretKind
    state: CredentialState = CredentialState.CAPTURED
    source: str = "unknown"           # dcsync / kerberoast / lsass / config / cracked
    domain: str | None = None
    #: Opaque handle into the credential vault — NEVER the raw secret in the model.
    secret_ref: str
    #: Masked preview for reports (e.g. first bytes of a hash) — never the full secret.
    masked: str = ""
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    created_at: str = Field(default_factory=lambda: utcnow().isoformat())

    @property
    def is_reusable(self) -> bool:
        """Whether this credential can be used to act as ``principal`` right now.

        A hash/key/ticket is directly reusable (PtH/PtT/Overpass); a roasted
        ticket is not until cracked (at which point a PLAINTEXT credential is
        minted from it).
        """

        return self.kind in _REUSABLE_KINDS
