"""Durable KnowledgeStore backend: persist → rehydrate → delete."""

from __future__ import annotations

from pathlib import Path

from attack_engine.knowledge.store import KnowledgeStore
from attack_engine.knowledge.store_backends import (
    MemoryKnowledgeBackend,
    SqliteKnowledgeBackend,
)
from attack_engine.schemas.findings import Asset, Finding, FindingState, Service


def _seed(store: KnowledgeStore) -> Finding:
    eid = store.engagement_id
    store.add_asset(
        Asset(address="10.5.0.12", engagement_id=eid,
              services=[Service(port=80, protocol="tcp", product="apache")]),
        reachable_from_entry=True,
    )
    f = Finding(engagement_id=eid, asset="10.5.0.12", type="lfi", title="LFI at page")
    store.propose_finding(f)
    store.promote_finding(f.id, FindingState.VERIFIED, verified_by="oracle")
    store.promote_finding(f.id, FindingState.CONFIRMED, verified_by="correlate")
    store.record_tool_run("katana", "10.5.0.12", "ok")
    return f


def test_sqlite_backend_rehydrates_after_restart(tmp_path: Path) -> None:
    db = str(tmp_path / "store.db")
    _seed(KnowledgeStore("eng-x", backend=SqliteKnowledgeBackend(db)))

    # simulate an API restart: a brand-new backend + store on the same file
    store2 = KnowledgeStore("eng-x", backend=SqliteKnowledgeBackend(db))
    assets, findings = store2.assets(), store2.findings()
    assert len(assets) == 1 and len(findings) == 1
    assert findings[0].state is FindingState.CONFIRMED       # promotion survived
    assert store2.graph.is_reachable(assets[0].id)            # graph rebuilt
    assert len(store2.tool_runs()) == 1                       # coverage survived


def test_sqlite_backend_isolates_engagements(tmp_path: Path) -> None:
    db = str(tmp_path / "store.db")
    _seed(KnowledgeStore("eng-x", backend=SqliteKnowledgeBackend(db)))
    other = KnowledgeStore("eng-other", backend=SqliteKnowledgeBackend(db))
    assert other.assets() == [] and other.findings() == []   # no cross-engagement bleed


def test_delete_purges_only_that_engagement(tmp_path: Path) -> None:
    db = str(tmp_path / "store.db")
    backend = SqliteKnowledgeBackend(db)
    _seed(KnowledgeStore("eng-x", backend=backend))
    _seed(KnowledgeStore("eng-y", backend=SqliteKnowledgeBackend(db)))
    backend.delete("eng-x")
    assert KnowledgeStore("eng-x", backend=SqliteKnowledgeBackend(db)).findings() == []
    assert KnowledgeStore("eng-y", backend=SqliteKnowledgeBackend(db)).findings()  # untouched


def test_memory_backend_is_ephemeral(tmp_path: Path) -> None:
    # the zero-service default: nothing persists, a new store starts empty
    _seed(KnowledgeStore("eng-x", backend=MemoryKnowledgeBackend()))
    assert KnowledgeStore("eng-x", backend=MemoryKnowledgeBackend()).findings() == []
