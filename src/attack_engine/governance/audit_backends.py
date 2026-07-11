"""Pluggable storage backends for the audit log.

The hashing/chaining lives in :mod:`attack_engine.governance.audit`; a backend
only has to store entries in append order and hand them back. Two ship in
Sprint 0:

* :class:`MemoryAuditBackend` — in-process, for tests and ephemeral runs.
* :class:`SqliteAuditBackend`  — durable single-node log; the table is written
  append-only (no UPDATE/DELETE in engine code) and raw blobs live alongside.

A Postgres backend slots in behind the same ABC in a later sprint.
"""

from __future__ import annotations

import sqlite3
import threading
from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..config import Settings
    from .audit import AuditEntry


class AuditBackend(ABC):
    """Storage contract. Implementations must preserve append order."""

    @abstractmethod
    def append(self, entry: AuditEntry, *, raw: bytes | None = None) -> None: ...

    @abstractmethod
    def head(self) -> AuditEntry | None: ...

    @abstractmethod
    def iter_entries(
        self, engagement_id: str | None = None
    ) -> Iterator[AuditEntry]: ...

    @abstractmethod
    def get_raw(self, audit_id: str) -> bytes | None: ...

    @abstractmethod
    def count(self) -> int: ...


class MemoryAuditBackend(AuditBackend):
    """Simple in-order list. Not durable; ideal for unit tests."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []
        self._raw: dict[str, bytes] = {}
        self._lock = threading.Lock()

    def append(self, entry: AuditEntry, *, raw: bytes | None = None) -> None:
        with self._lock:
            self._entries.append(entry)
            if raw is not None:
                self._raw[entry.entry_hash] = raw

    def head(self) -> AuditEntry | None:
        with self._lock:
            return self._entries[-1] if self._entries else None

    def iter_entries(self, engagement_id: str | None = None) -> Iterator[AuditEntry]:
        with self._lock:
            snapshot = list(self._entries)
        for e in snapshot:
            if engagement_id is None or e.engagement_id == engagement_id:
                yield e

    def get_raw(self, audit_id: str) -> bytes | None:
        return self._raw.get(audit_id)

    def count(self) -> int:
        return len(self._entries)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    seq            INTEGER PRIMARY KEY,
    ts             TEXT    NOT NULL,
    engagement_id  TEXT    NOT NULL,
    actor          TEXT    NOT NULL,
    action         TEXT    NOT NULL,
    target         TEXT,
    payload_json   TEXT    NOT NULL,
    raw_sha256     TEXT,
    prev_hash      TEXT    NOT NULL,
    entry_hash     TEXT    NOT NULL UNIQUE,
    raw_blob       BLOB
);
CREATE INDEX IF NOT EXISTS idx_audit_engagement ON audit_log(engagement_id);
"""


class SqliteAuditBackend(AuditBackend):
    """Durable, append-only SQLite backend.

    The engine only ever INSERTs; there is no code path that UPDATEs or DELETEs
    a row. Combined with the hash chain, that makes tampering detectable even
    if someone edits the file directly. Uses WAL for concurrent readers.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        if self._path.parent and str(self._path.parent) not in ("", "."):
            self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            str(self._path), check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._conn.executescript(_SCHEMA)

    def _row_to_entry(self, row: sqlite3.Row) -> AuditEntry:
        import json

        from .audit import AuditEntry

        return AuditEntry(
            seq=row["seq"],
            ts=row["ts"],
            engagement_id=row["engagement_id"],
            actor=row["actor"],
            action=row["action"],
            target=row["target"],
            payload=json.loads(row["payload_json"]),
            raw_sha256=row["raw_sha256"],
            prev_hash=row["prev_hash"],
            entry_hash=row["entry_hash"],
        )

    def append(self, entry: AuditEntry, *, raw: bytes | None = None) -> None:
        import json

        with self._lock:
            self._conn.execute(
                """
                INSERT INTO audit_log
                    (seq, ts, engagement_id, actor, action, target,
                     payload_json, raw_sha256, prev_hash, entry_hash, raw_blob)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.seq,
                    entry.ts,
                    entry.engagement_id,
                    entry.actor,
                    entry.action,
                    entry.target,
                    json.dumps(entry.payload, sort_keys=True, separators=(",", ":")),
                    entry.raw_sha256,
                    entry.prev_hash,
                    entry.entry_hash,
                    raw,
                ),
            )

    def head(self) -> AuditEntry | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM audit_log ORDER BY seq DESC LIMIT 1"
            ).fetchone()
        return self._row_to_entry(row) if row else None

    def iter_entries(self, engagement_id: str | None = None) -> Iterator[AuditEntry]:
        with self._lock:
            if engagement_id is None:
                rows = self._conn.execute(
                    "SELECT * FROM audit_log ORDER BY seq ASC"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM audit_log WHERE engagement_id = ? ORDER BY seq ASC",
                    (engagement_id,),
                ).fetchall()
        for row in rows:
            yield self._row_to_entry(row)

    def get_raw(self, audit_id: str) -> bytes | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT raw_blob FROM audit_log WHERE entry_hash = ?", (audit_id,)
            ).fetchone()
        if row is None:
            return None
        blob = row["raw_blob"]
        return bytes(blob) if blob is not None else None

    def count(self) -> int:
        with self._lock:
            return int(
                self._conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()


_PG_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    seq            BIGINT PRIMARY KEY,
    ts             TEXT NOT NULL,
    engagement_id  TEXT NOT NULL,
    actor          TEXT NOT NULL,
    action         TEXT NOT NULL,
    target         TEXT,
    payload_json   TEXT NOT NULL,
    raw_sha256     TEXT,
    prev_hash      TEXT NOT NULL,
    entry_hash     TEXT NOT NULL UNIQUE,
    raw_blob       BYTEA
);
CREATE INDEX IF NOT EXISTS idx_audit_engagement ON audit_log(engagement_id);
"""


class PostgresAuditBackend(AuditBackend):
    """Durable, append-only Postgres backend for multi-node deployments.

    Same guarantees as the SQLite backend — the engine only INSERTs, and the
    hash chain makes tampering detectable — but shared across processes/nodes.
    Requires the ``postgres`` extra (``psycopg``).
    """

    def __init__(self, dsn: str) -> None:
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "the 'postgres' extra is not installed; "
                "install attack-engine[postgres] to use PostgresAuditBackend"
            ) from exc
        self._psycopg = psycopg
        self._lock = threading.Lock()
        self._conn = psycopg.connect(dsn, autocommit=True)
        self._conn.execute(_PG_SCHEMA)

    def _row_to_entry(self, row: tuple[Any, ...]) -> AuditEntry:
        import json

        from .audit import AuditEntry

        return AuditEntry(
            seq=int(row[0]), ts=str(row[1]), engagement_id=str(row[2]),
            actor=str(row[3]), action=str(row[4]),
            target=row[5] if row[5] is None else str(row[5]),
            payload=json.loads(str(row[6])),
            raw_sha256=row[7] if row[7] is None else str(row[7]),
            prev_hash=str(row[8]), entry_hash=str(row[9]),
        )

    def append(self, entry: AuditEntry, *, raw: bytes | None = None) -> None:
        import json

        with self._lock:
            self._conn.execute(
                "INSERT INTO audit_log (seq, ts, engagement_id, actor, action, target,"
                " payload_json, raw_sha256, prev_hash, entry_hash, raw_blob)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (entry.seq, entry.ts, entry.engagement_id, entry.actor, entry.action,
                 entry.target,
                 json.dumps(entry.payload, sort_keys=True, separators=(",", ":")),
                 entry.raw_sha256, entry.prev_hash, entry.entry_hash, raw),
            )

    def head(self) -> AuditEntry | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT seq, ts, engagement_id, actor, action, target, payload_json,"
                " raw_sha256, prev_hash, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
            ).fetchone()
        return self._row_to_entry(row) if row else None

    def iter_entries(self, engagement_id: str | None = None) -> Iterator[AuditEntry]:
        q = ("SELECT seq, ts, engagement_id, actor, action, target, payload_json,"
             " raw_sha256, prev_hash, entry_hash FROM audit_log")
        params: tuple[Any, ...] = ()
        if engagement_id is not None:
            q += " WHERE engagement_id = %s"
            params = (engagement_id,)
        q += " ORDER BY seq ASC"
        with self._lock:
            rows = self._conn.execute(q, params).fetchall()
        for row in rows:
            yield self._row_to_entry(row)

    def get_raw(self, audit_id: str) -> bytes | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT raw_blob FROM audit_log WHERE entry_hash = %s", (audit_id,)
            ).fetchone()
        if row is None or row[0] is None:
            return None
        return bytes(row[0])

    def count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()
        return int(row[0]) if row else 0

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def build_audit_backend(settings: Settings | None = None) -> AuditBackend:
    """Construct the configured audit backend: memory, sqlite, or postgres."""

    from ..config import AuditBackend as Kind
    from ..config import get_settings

    s: Settings = settings or get_settings()
    if s.audit_backend is Kind.MEMORY:
        return MemoryAuditBackend()
    if s.audit_backend is Kind.SQLITE:
        return SqliteAuditBackend(s.audit_sqlite_path)
    if s.audit_backend is Kind.POSTGRES:
        if s.audit_postgres_dsn is None:
            raise RuntimeError("AE_AUDIT_POSTGRES_DSN must be set for the postgres backend")
        return PostgresAuditBackend(s.audit_postgres_dsn.get_secret_value())
    raise NotImplementedError(f"audit backend {s.audit_backend.value!r} unavailable")
