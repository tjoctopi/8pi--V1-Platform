"""Durable persistence for engagement RESULTS so they survive an API restart.

The :class:`~attack_engine.knowledge.store.KnowledgeStore` keeps assets, findings,
remediations and tool-runs in memory. Without a durable backend those vanish when
the API process restarts (deploy / crash / reboot), so a re-opened engagement shows
zero results until it is re-run. A :class:`KnowledgeBackend` persists each mutation
and lets the store **rehydrate** on re-open.

Backends mirror the audit-log ones (memory → sqlite → postgres, one env var):

* :class:`MemoryKnowledgeBackend` — no durability (the zero-service default; the
  store's own dicts are the source of truth).
* :class:`SqliteKnowledgeBackend`  — durable single-node store (the pilot default).
* :class:`PostgresKnowledgeBackend` — durable multi-node store (scale-out).

Models are stored as JSON blobs keyed by engagement id — robust to schema growth and
enough for the console's read/rehydrate needs (structured querying stays in-process).
"""

from __future__ import annotations

import json
import sqlite3
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..schemas.findings import Asset, Finding
from ..schemas.remediation import Remediation
from ..schemas.tools import ToolRunRecord

if TYPE_CHECKING:
    from ..config import Settings


@dataclass
class KnowledgeSnapshot:
    """Everything needed to rehydrate a store for one engagement."""

    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    remediations: list[Remediation] = field(default_factory=list)
    tool_runs: list[ToolRunRecord] = field(default_factory=list)


class KnowledgeBackend(ABC):
    """Persist engagement results + load them back for rehydrate."""

    @abstractmethod
    def save_asset(self, engagement_id: str, asset: Asset) -> None: ...

    @abstractmethod
    def save_finding(self, engagement_id: str, finding: Finding) -> None: ...

    @abstractmethod
    def save_remediation(self, engagement_id: str, remediation: Remediation) -> None: ...

    @abstractmethod
    def save_tool_run(self, engagement_id: str, run: ToolRunRecord) -> None: ...

    @abstractmethod
    def save_agent_run(self, engagement_id: str, run: dict[str, Any]) -> None: ...

    @abstractmethod
    def load(self, engagement_id: str) -> KnowledgeSnapshot: ...

    @abstractmethod
    def load_agent_runs(self, engagement_id: str) -> list[dict[str, Any]]: ...

    @abstractmethod
    def delete(self, engagement_id: str) -> None:
        """Purge all persisted results for an engagement (the audit log is separate
        and immutable — deletion never touches it)."""


class MemoryKnowledgeBackend(KnowledgeBackend):
    """No durability — the store's in-memory dicts are the source of truth.

    Preserves the zero-service default: nothing is written, ``load`` is empty, so a
    fresh process starts with an empty store (unchanged behaviour).
    """

    def save_asset(self, engagement_id: str, asset: Asset) -> None:
        return None

    def save_finding(self, engagement_id: str, finding: Finding) -> None:
        return None

    def save_remediation(self, engagement_id: str, remediation: Remediation) -> None:
        return None

    def save_tool_run(self, engagement_id: str, run: ToolRunRecord) -> None:
        return None

    def save_agent_run(self, engagement_id: str, run: dict[str, Any]) -> None:
        return None

    def load(self, engagement_id: str) -> KnowledgeSnapshot:
        return KnowledgeSnapshot()

    def load_agent_runs(self, engagement_id: str) -> list[dict[str, Any]]:
        return []

    def delete(self, engagement_id: str) -> None:
        return None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS ke_assets (
    engagement_id TEXT NOT NULL, asset_id TEXT NOT NULL, doc TEXT NOT NULL,
    PRIMARY KEY (engagement_id, asset_id));
CREATE TABLE IF NOT EXISTS ke_findings (
    engagement_id TEXT NOT NULL, finding_id TEXT NOT NULL, doc TEXT NOT NULL,
    PRIMARY KEY (engagement_id, finding_id));
CREATE TABLE IF NOT EXISTS ke_remediations (
    engagement_id TEXT NOT NULL, remediation_id TEXT NOT NULL, doc TEXT NOT NULL,
    PRIMARY KEY (engagement_id, remediation_id));
CREATE TABLE IF NOT EXISTS ke_tool_runs (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, engagement_id TEXT NOT NULL, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ke_agent_runs (
    engagement_id TEXT NOT NULL, run_id TEXT NOT NULL, doc TEXT NOT NULL,
    PRIMARY KEY (engagement_id, run_id));
CREATE INDEX IF NOT EXISTS ix_ke_tool_runs_eng ON ke_tool_runs (engagement_id);
"""


class SqliteKnowledgeBackend(KnowledgeBackend):
    """Durable single-node results store (the pilot default). WAL for concurrency."""

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
        self._conn.executescript(_SCHEMA)

    def _upsert(self, table: str, key_col: str, eid: str, key: str, doc: str) -> None:
        with self._lock:
            self._conn.execute(
                f"INSERT INTO {table} (engagement_id, {key_col}, doc) VALUES (?, ?, ?) "
                f"ON CONFLICT(engagement_id, {key_col}) DO UPDATE SET doc=excluded.doc",
                (eid, key, doc),
            )

    def save_asset(self, engagement_id: str, asset: Asset) -> None:
        self._upsert("ke_assets", "asset_id", engagement_id, asset.id,
                     asset.model_dump_json())

    def save_finding(self, engagement_id: str, finding: Finding) -> None:
        self._upsert("ke_findings", "finding_id", engagement_id, finding.id,
                     finding.model_dump_json())

    def save_remediation(self, engagement_id: str, remediation: Remediation) -> None:
        self._upsert("ke_remediations", "remediation_id", engagement_id,
                     remediation.id, remediation.model_dump_json())

    def save_tool_run(self, engagement_id: str, run: ToolRunRecord) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO ke_tool_runs (engagement_id, doc) VALUES (?, ?)",
                (engagement_id, run.model_dump_json()),
            )

    def save_agent_run(self, engagement_id: str, run: dict[str, Any]) -> None:
        self._upsert("ke_agent_runs", "run_id", engagement_id,
                     str(run.get("id")), json.dumps(run))

    def load(self, engagement_id: str) -> KnowledgeSnapshot:
        with self._lock:
            def rows(table: str) -> list[str]:
                cur = self._conn.execute(
                    f"SELECT doc FROM {table} WHERE engagement_id=? ORDER BY rowid",
                    (engagement_id,),
                )
                return [r["doc"] for r in cur.fetchall()]

            return KnowledgeSnapshot(
                assets=[Asset.model_validate_json(d) for d in rows("ke_assets")],
                findings=[Finding.model_validate_json(d) for d in rows("ke_findings")],
                remediations=[Remediation.model_validate_json(d)
                              for d in rows("ke_remediations")],
                tool_runs=[ToolRunRecord.model_validate_json(d)
                           for d in rows("ke_tool_runs")],
            )

    def load_agent_runs(self, engagement_id: str) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT doc FROM ke_agent_runs WHERE engagement_id=? ORDER BY rowid",
                (engagement_id,),
            )
            return [json.loads(r["doc"]) for r in cur.fetchall()]

    def delete(self, engagement_id: str) -> None:
        with self._lock:
            for table in ("ke_assets", "ke_findings", "ke_remediations",
                          "ke_tool_runs", "ke_agent_runs"):
                self._conn.execute(
                    f"DELETE FROM {table} WHERE engagement_id=?", (engagement_id,))


class PostgresKnowledgeBackend(KnowledgeBackend):  # pragma: no cover - integration only
    """Durable multi-node results store (scale-out). Same JSON-blob model as SQLite."""

    def __init__(self, dsn: str) -> None:
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError(
                "install attack-engine[postgres] to use PostgresKnowledgeBackend"
            ) from exc

        self._dsn = dsn
        self._lock = threading.Lock()
        self._conn = psycopg.connect(dsn, autocommit=True)
        with self._conn.cursor() as cur:
            cur.execute(_SCHEMA.replace("AUTOINCREMENT", "").replace(
                "INTEGER PRIMARY KEY", "BIGSERIAL PRIMARY KEY"))

    def _upsert(self, table: str, key_col: str, eid: str, key: str, doc: str) -> None:
        with self._lock, self._conn.cursor() as cur:
            cur.execute(
                f"INSERT INTO {table} (engagement_id, {key_col}, doc) VALUES (%s, %s, %s) "
                f"ON CONFLICT (engagement_id, {key_col}) DO UPDATE SET doc=EXCLUDED.doc",
                (eid, key, doc),
            )

    def save_asset(self, engagement_id: str, asset: Asset) -> None:
        self._upsert("ke_assets", "asset_id", engagement_id, asset.id, asset.model_dump_json())

    def save_finding(self, engagement_id: str, finding: Finding) -> None:
        self._upsert("ke_findings", "finding_id", engagement_id, finding.id,
                     finding.model_dump_json())

    def save_remediation(self, engagement_id: str, remediation: Remediation) -> None:
        self._upsert("ke_remediations", "remediation_id", engagement_id,
                     remediation.id, remediation.model_dump_json())

    def save_tool_run(self, engagement_id: str, run: ToolRunRecord) -> None:
        with self._lock, self._conn.cursor() as cur:
            cur.execute("INSERT INTO ke_tool_runs (engagement_id, doc) VALUES (%s, %s)",
                        (engagement_id, run.model_dump_json()))

    def save_agent_run(self, engagement_id: str, run: dict[str, Any]) -> None:
        self._upsert("ke_agent_runs", "run_id", engagement_id, str(run.get("id")),
                     json.dumps(run))

    def load(self, engagement_id: str) -> KnowledgeSnapshot:
        def rows(table: str) -> list[str]:
            with self._lock, self._conn.cursor() as cur:
                cur.execute(f"SELECT doc FROM {table} WHERE engagement_id=%s", (engagement_id,))
                return [r[0] for r in cur.fetchall()]

        return KnowledgeSnapshot(
            assets=[Asset.model_validate_json(d) for d in rows("ke_assets")],
            findings=[Finding.model_validate_json(d) for d in rows("ke_findings")],
            remediations=[Remediation.model_validate_json(d) for d in rows("ke_remediations")],
            tool_runs=[ToolRunRecord.model_validate_json(d) for d in rows("ke_tool_runs")],
        )

    def load_agent_runs(self, engagement_id: str) -> list[dict[str, Any]]:
        with self._lock, self._conn.cursor() as cur:
            cur.execute("SELECT doc FROM ke_agent_runs WHERE engagement_id=%s", (engagement_id,))
            return [json.loads(r[0]) for r in cur.fetchall()]

    def delete(self, engagement_id: str) -> None:
        with self._lock, self._conn.cursor() as cur:
            for table in ("ke_assets", "ke_findings", "ke_remediations",
                          "ke_tool_runs", "ke_agent_runs"):
                cur.execute(f"DELETE FROM {table} WHERE engagement_id=%s", (engagement_id,))


def build_knowledge_backend(settings: Settings | None = None) -> KnowledgeBackend:
    """Construct the results store backend from config (mirrors build_audit_backend)."""

    from ..config import StoreBackend, get_settings

    s = settings or get_settings()
    if s.store_backend is StoreBackend.SQLITE:
        return SqliteKnowledgeBackend(s.store_sqlite_path)
    if s.store_backend is StoreBackend.POSTGRES:
        dsn = s.store_postgres_dsn.get_secret_value() if s.store_postgres_dsn else None
        if not dsn:
            raise RuntimeError("AE_STORE_POSTGRES_DSN required for the postgres store backend")
        return PostgresKnowledgeBackend(dsn)
    return MemoryKnowledgeBackend()
