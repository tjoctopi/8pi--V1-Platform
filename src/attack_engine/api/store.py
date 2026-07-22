"""Shell-side persistence (SQLite, stdlib only).

The engine owns the *security* state (scope, findings, gates, audit chain). This
store owns only the **shell** state an HTTP product needs and the engine
deliberately doesn't model: user accounts and the engagement metadata the
console lists (name, lifecycle status, the editable RoE draft, archive flag).

SQLite keeps us consistent with the engine's zero-external-services principle —
no Mongo, no server to stand up. One file, created on first use.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY,
    email        TEXT UNIQUE NOT NULL,
    name         TEXT NOT NULL,
    role         TEXT NOT NULL,
    pw_hash      TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_login   TEXT
);
CREATE TABLE IF NOT EXISTS engagements (
    id           TEXT PRIMARY KEY,
    doc          TEXT NOT NULL,   -- JSON engagement metadata
    created_at   TEXT NOT NULL
);
"""


class ShellStore:
    """Thin, thread-safe SQLite wrapper for users + engagement metadata."""

    def __init__(self, path: str | Path = "./data/api_shell.db") -> None:
        self._path = str(path)
        if self._path != ":memory:":
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ── users ──────────────────────────────────────────────────────────────
    def create_user(self, user: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO users (id,email,name,role,pw_hash,created_at,last_login) "
                "VALUES (?,?,?,?,?,?,?)",
                (
                    user["id"], user["email"].lower(), user["name"], user["role"],
                    user["pw_hash"], user["created_at"], user.get("last_login"),
                ),
            )
            self._conn.commit()

    def user_by_email(self, email: str) -> dict[str, Any] | None:
        cur = self._conn.execute(
            "SELECT * FROM users WHERE email=?", (email.lower(),)
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def user_by_id(self, uid: str) -> dict[str, Any] | None:
        cur = self._conn.execute("SELECT * FROM users WHERE id=?", (uid,))
        row = cur.fetchone()
        return dict(row) if row else None

    def list_users(self) -> list[dict[str, Any]]:
        cur = self._conn.execute("SELECT * FROM users ORDER BY created_at")
        return [dict(r) for r in cur.fetchall()]

    def delete_user(self, uid: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM users WHERE id=?", (uid,))
            self._conn.commit()

    def touch_login(self, uid: str, ts: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE users SET last_login=? WHERE id=?", (ts, uid))
            self._conn.commit()

    def user_count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    # ── engagements (metadata JSON blob) ─────────────────────────────────────
    def save_engagement(self, doc: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO engagements (id,doc,created_at) VALUES (?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET doc=excluded.doc",
                (doc["id"], json.dumps(doc), doc.get("created_at", "")),
            )
            self._conn.commit()

    def get_engagement(self, eid: str) -> dict[str, Any] | None:
        cur = self._conn.execute("SELECT doc FROM engagements WHERE id=?", (eid,))
        row = cur.fetchone()
        return json.loads(row["doc"]) if row else None

    def list_engagements(self) -> list[dict[str, Any]]:
        cur = self._conn.execute("SELECT doc FROM engagements ORDER BY created_at DESC")
        return [json.loads(r["doc"]) for r in cur.fetchall()]

    def delete_engagement(self, eid: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM engagements WHERE id=?", (eid,))
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()
