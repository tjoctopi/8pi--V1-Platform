"""Immutable, hash-chained audit log.

Every security-relevant action appends one :class:`AuditEntry`. Each entry
carries the hash of the previous one, so the whole log forms a tamper-evident
chain: altering or deleting any past entry breaks every hash after it, which
:meth:`AuditLog.verify` detects.

    entry_hash = sha256( canonical(seq, ts, engagement, actor, action,
                                    target, payload, raw_sha256, prev_hash) )

Raw tool output is hashed into the entry (``raw_sha256``) and, optionally,
stored full-fidelity by the backend — the digest binds the bytes to the chain
even if the blob lives elsewhere. Backends are pluggable (in-memory for tests,
SQLite for a durable single-node log, Postgres later); the hashing lives here
so integrity is identical across all of them.
"""

from __future__ import annotations

import hashlib
import json
import threading
from typing import Any

from ..errors import AuditIntegrityError
from ..schemas.common import StrictModel, iso_now
from .audit_backends import AuditBackend, MemoryAuditBackend

GENESIS_HASH = "0" * 64


class AuditEntry(StrictModel):
    """One immutable link in the audit chain."""

    seq: int
    ts: str
    engagement_id: str
    actor: str  # agent id / component name
    action: str  # e.g. "tool.run", "scope.refuse", "gate.request", "finding.promote"
    target: str | None = None
    payload: dict[str, Any] = {}
    raw_sha256: str | None = None  # digest of full-fidelity raw output, if any
    prev_hash: str
    entry_hash: str

    def signing_bytes(self) -> bytes:
        """The canonical, deterministic serialization that gets hashed.

        Excludes ``entry_hash`` itself (it is the output). Uses sorted keys and
        compact separators so the digest is stable across processes/versions.
        """

        core = {
            "seq": self.seq,
            "ts": self.ts,
            "engagement_id": self.engagement_id,
            "actor": self.actor,
            "action": self.action,
            "target": self.target,
            "payload": self.payload,
            "raw_sha256": self.raw_sha256,
            "prev_hash": self.prev_hash,
        }
        return json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def compute_hash(self) -> str:
        return hashlib.sha256(self.signing_bytes()).hexdigest()


def _digest_raw(raw: bytes | None) -> str | None:
    if raw is None:
        return None
    return hashlib.sha256(raw).hexdigest()


class AuditLog:
    """Append-only, hash-chained log facade over a pluggable backend.

    Thread-safe: appends serialise through a lock so the chain stays linear
    even under concurrent agents. This is one of the two components that must
    exist before any offensive tool is wired.
    """

    def __init__(self, backend: AuditBackend | None = None) -> None:
        self._backend = backend or MemoryAuditBackend()
        self._lock = threading.Lock()

    @property
    def backend(self) -> AuditBackend:
        return self._backend

    def append(
        self,
        *,
        engagement_id: str,
        actor: str,
        action: str,
        target: str | None = None,
        payload: dict[str, Any] | None = None,
        raw: bytes | None = None,
    ) -> AuditEntry:
        """Append a new entry and return it. The returned ``entry_hash`` is the
        stable id callers store as evidence (``audit_id``)."""

        with self._lock:
            head = self._backend.head()
            seq = (head.seq + 1) if head else 1
            prev_hash = head.entry_hash if head else GENESIS_HASH
            entry = AuditEntry(
                seq=seq,
                ts=iso_now(),
                engagement_id=engagement_id,
                actor=actor,
                action=action,
                target=target,
                payload=payload or {},
                raw_sha256=_digest_raw(raw),
                prev_hash=prev_hash,
                entry_hash="",  # placeholder; set below
            )
            # Seal the entry: compute the chain hash over the finalized fields.
            entry = entry.model_copy(update={"entry_hash": entry.compute_hash()})
            self._backend.append(entry, raw=raw)
            return entry

    def head(self) -> AuditEntry | None:
        return self._backend.head()

    def entries(self, engagement_id: str | None = None) -> list[AuditEntry]:
        return list(self._backend.iter_entries(engagement_id=engagement_id))

    def get_raw(self, entry: AuditEntry | str) -> bytes | None:
        audit_id = entry.entry_hash if isinstance(entry, AuditEntry) else entry
        return self._backend.get_raw(audit_id)

    def verify(self) -> bool:
        """Recompute the whole chain; raise :class:`AuditIntegrityError` on any
        break. Returns ``True`` when intact.

        Verifies three invariants per entry: (1) monotonic ``seq``, (2)
        ``prev_hash`` links to the actual predecessor, and (3) the stored
        ``entry_hash`` matches a fresh recomputation.
        """

        prev_hash = GENESIS_HASH
        expected_seq = 1
        for entry in self._backend.iter_entries():
            if entry.seq != expected_seq:
                raise AuditIntegrityError(
                    f"seq gap: expected {expected_seq}, found {entry.seq}"
                )
            if entry.prev_hash != prev_hash:
                raise AuditIntegrityError(
                    f"broken link at seq {entry.seq}: prev_hash mismatch"
                )
            recomputed = entry.compute_hash()
            if recomputed != entry.entry_hash:
                raise AuditIntegrityError(
                    f"tampered entry at seq {entry.seq}: hash mismatch"
                )
            prev_hash = entry.entry_hash
            expected_seq += 1
        return True

    def __len__(self) -> int:
        return self._backend.count()
