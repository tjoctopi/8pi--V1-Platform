"""Credential vault — the one place raw secret material lives (Phase E3).

Data minimization (rule §6/§8): a :class:`~attack_engine.schemas.credentials.Credential`
carries only an opaque ``secret_ref`` and a masked preview — never the secret. The
vault is the single chokepoint that holds the actual material, hands out refs, and
produces masked previews. In production it is backed by an encrypted-at-rest,
access-controlled store; the in-memory backend here keeps the test suite free of
external services while presenting the exact same interface.

The vault **never logs raw material**, and ``mask()`` is the only way material
reaches a report — so a cracked password or an NT hash cannot leak through the
model, an audit payload, or a log line.
"""

from __future__ import annotations

from ..logging import get_logger
from ..schemas.common import new_id

_log = get_logger("credentials.vault")


def mask(secret: str) -> str:
    """A safe-to-display preview of a secret — enough to recognize, not to use.

    A short secret is fully redacted (revealing 2 of 4 chars is most of it);
    a longer one shows a few leading chars then a fixed redaction so previews
    never leak length precisely.
    """

    if len(secret) <= 4:
        return "****"
    return f"{secret[:3]}…****"


class CredentialVault:
    """Holds raw secret material behind opaque refs. In-memory backend.

    The stored value is the *material* (a plaintext password, a hex NT hash, a
    ``$krb5tgs$`` roast blob) keyed by an opaque ref. Callers pass the ref around;
    only the cracker (to read material) and reporting (via :meth:`preview`) touch
    the vault, and reporting never receives the raw value.
    """

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    def put(self, material: str) -> str:
        """Store raw material and return an opaque ref. Never logs the material."""

        ref = new_id("vault")
        self._store[ref] = material
        _log.debug("vault stored material", ref=ref, bytes=len(material))
        return ref

    def get(self, ref: str) -> str:
        """Read raw material by ref (cracker-only path). Raises on unknown ref."""

        try:
            return self._store[ref]
        except KeyError:
            raise KeyError(f"unknown credential ref: {ref}") from None

    def has(self, ref: str) -> bool:
        return ref in self._store

    def preview(self, ref: str) -> str:
        """A masked preview of the material behind ``ref`` — safe for reports."""

        return mask(self._store[ref]) if ref in self._store else "****"

    def purge(self, ref: str) -> bool:
        """Remove material (end-of-engagement hygiene). Returns whether it existed."""

        existed = self._store.pop(ref, None) is not None
        if existed:
            _log.debug("vault purged material", ref=ref)
        return existed

    def __len__(self) -> int:
        return len(self._store)
