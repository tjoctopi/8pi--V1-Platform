"""Audit log tests — the tamper-evident chain that must exist before offense.

Parametrised across both Sprint 0 backends so the integrity guarantees are
identical whether entries live in memory or on disk.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from attack_engine.errors import AuditIntegrityError
from attack_engine.governance.audit import GENESIS_HASH, AuditLog
from attack_engine.governance.audit_backends import (
    MemoryAuditBackend,
    SqliteAuditBackend,
)


@pytest.fixture(params=["memory", "sqlite"])
def audit(request: pytest.FixtureRequest, tmp_path: Path) -> AuditLog:
    if request.param == "memory":
        return AuditLog(MemoryAuditBackend())
    return AuditLog(SqliteAuditBackend(tmp_path / "audit.db"))


def test_first_entry_links_to_genesis(audit: AuditLog) -> None:
    entry = audit.append(engagement_id="eng-1", actor="mapper", action="tool.run")
    assert entry.seq == 1
    assert entry.prev_hash == GENESIS_HASH
    assert entry.entry_hash and entry.entry_hash != GENESIS_HASH


def test_chain_links_are_contiguous(audit: AuditLog) -> None:
    e1 = audit.append(engagement_id="eng-1", actor="a", action="x")
    e2 = audit.append(engagement_id="eng-1", actor="a", action="y")
    e3 = audit.append(engagement_id="eng-1", actor="a", action="z")
    assert e2.prev_hash == e1.entry_hash
    assert e3.prev_hash == e2.entry_hash
    assert [e.seq for e in (e1, e2, e3)] == [1, 2, 3]


def test_verify_passes_on_intact_chain(audit: AuditLog) -> None:
    for i in range(10):
        audit.append(engagement_id="eng-1", actor="a", action=f"act-{i}")
    assert audit.verify() is True
    assert len(audit) == 10


def test_raw_bytes_hashed_and_retrievable(audit: AuditLog) -> None:
    raw = b"PORT   STATE SERVICE\n80/tcp open  http\n"
    entry = audit.append(
        engagement_id="eng-1", actor="mapper", action="tool.run",
        target="10.0.4.12", raw=raw,
    )
    assert entry.raw_sha256 is not None
    assert audit.get_raw(entry) == raw
    assert audit.get_raw(entry.entry_hash) == raw


def test_hash_recomputation_is_stable() -> None:
    # An entry's stored hash must equal a fresh recomputation over its fields,
    # proving the canonical serialization is deterministic (key order etc.).
    a = AuditLog(MemoryAuditBackend())
    e = a.append(engagement_id="eng-1", actor="a", action="x", target="t",
                 payload={"z": 1, "a": 2})
    assert e.compute_hash() == e.entry_hash


def test_engagement_filter(audit: AuditLog) -> None:
    audit.append(engagement_id="eng-1", actor="a", action="x")
    audit.append(engagement_id="eng-2", actor="a", action="y")
    audit.append(engagement_id="eng-1", actor="a", action="z")
    eng1 = audit.entries("eng-1")
    assert len(eng1) == 2
    assert all(e.engagement_id == "eng-1" for e in eng1)


class TestTamperDetection:
    def test_memory_backend_mutated_payload_detected(self) -> None:
        backend = MemoryAuditBackend()
        audit = AuditLog(backend)
        audit.append(engagement_id="eng-1", actor="a", action="x")
        audit.append(engagement_id="eng-1", actor="a", action="y")
        # Tamper: rewrite a past entry's action without recomputing its hash.
        tampered = backend._entries[0].model_copy(update={"action": "EVIL"})
        backend._entries[0] = tampered
        with pytest.raises(AuditIntegrityError, match=r"tampered|hash mismatch"):
            audit.verify()

    def test_broken_link_detected(self) -> None:
        backend = MemoryAuditBackend()
        audit = AuditLog(backend)
        audit.append(engagement_id="eng-1", actor="a", action="x")
        audit.append(engagement_id="eng-1", actor="a", action="y")
        # Drop the first entry → the second's prev_hash no longer links.
        del backend._entries[0]
        backend._entries[0] = backend._entries[0].model_copy(update={"seq": 1})
        with pytest.raises(AuditIntegrityError):
            audit.verify()

    def test_sqlite_direct_row_edit_detected(self, tmp_path: Path) -> None:
        db = tmp_path / "audit.db"
        audit = AuditLog(SqliteAuditBackend(db))
        audit.append(engagement_id="eng-1", actor="a", action="x")
        audit.append(engagement_id="eng-1", actor="a", action="y")
        # Simulate an attacker editing the DB file directly.
        conn = sqlite3.connect(str(db))
        conn.execute("UPDATE audit_log SET action='EVIL' WHERE seq=1")
        conn.commit()
        conn.close()
        reopened = AuditLog(SqliteAuditBackend(db))
        with pytest.raises(AuditIntegrityError):
            reopened.verify()


def test_sqlite_persists_across_reopen(tmp_path: Path) -> None:
    db = tmp_path / "audit.db"
    a1 = AuditLog(SqliteAuditBackend(db))
    a1.append(engagement_id="eng-1", actor="a", action="x", raw=b"hello")
    a1.append(engagement_id="eng-1", actor="a", action="y")
    a2 = AuditLog(SqliteAuditBackend(db))
    assert len(a2) == 2
    assert a2.verify() is True
    # raw blob survived the reopen
    first = a2.entries("eng-1")[0]
    assert a2.get_raw(first) == b"hello"
