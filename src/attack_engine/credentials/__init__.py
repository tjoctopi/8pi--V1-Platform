"""Credential lifecycle (Phase E3): capture → crack → reuse/own → escalate.

An identity *lead* (a roastable account, a dumped hash) becomes identity *power*
only when the fleet can act **as** that principal. This package turns captured
secret material into a usable, owned credential and folds the new capability back
into the world model's identity attack graph — owning a principal re-plans the
path to Domain Admin.

- :class:`~attack_engine.credentials.vault.CredentialVault` — holds raw material
  behind opaque refs (data minimization; the :class:`Credential` model never
  carries the secret).
- :class:`~attack_engine.credentials.cracker.HashCracker` — real offline cracking
  of NT hashes and Kerberos roast tickets (TGS-REP / AS-REP, RC4-HMAC).
- :class:`~attack_engine.credentials.manager.CredentialManager` — the governed
  lifecycle: capture material, crack it, and own the principal.
"""

from __future__ import annotations

from .cracker import CrackResult, HashCracker
from .manager import CredentialManager
from .vault import CredentialVault

__all__ = [
    "CrackResult",
    "CredentialManager",
    "CredentialVault",
    "HashCracker",
]
