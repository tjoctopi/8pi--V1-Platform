"""Live-backend integration tests.

These prove the pluggable backends against *real* servers. They are skipped
unless the relevant driver is installed AND a connection string is provided via
env, so the default offline suite never touches them:

    AE_TEST_POSTGRES_DSN   e.g. postgresql://user:pass@localhost:5432/ae_test
    AE_TEST_REDIS_URL      e.g. redis://localhost:6379/1
    AE_TEST_NEO4J_URL      e.g. bolt://neo4j:pass@localhost:7687

Run with:  pytest -m integration
"""

from __future__ import annotations

import importlib.util
import os

import pytest

pytestmark = pytest.mark.integration


def _have(mod: str) -> bool:
    return importlib.util.find_spec(mod) is not None


# --- Postgres audit backend ---------------------------------------------------

_PG_DSN = os.getenv("AE_TEST_POSTGRES_DSN")


@pytest.mark.skipif(not (_PG_DSN and _have("psycopg")), reason="no postgres DSN/driver")
def test_postgres_audit_chain_live() -> None:
    from attack_engine.governance.audit import AuditLog
    from attack_engine.governance.audit_backends import PostgresAuditBackend

    backend = PostgresAuditBackend(_PG_DSN)  # type: ignore[arg-type]
    audit = AuditLog(backend)
    audit.append(engagement_id="eng-it", actor="test", action="x", raw=b"hello")
    audit.append(engagement_id="eng-it", actor="test", action="y")
    assert audit.verify() is True
    assert audit.get_raw(audit.entries("eng-it")[0]) == b"hello"
    backend.close()


# --- Redis Streams event bus --------------------------------------------------

_REDIS_URL = os.getenv("AE_TEST_REDIS_URL")


@pytest.mark.skipif(not (_REDIS_URL and _have("redis")), reason="no redis url/driver")
def test_redis_eventbus_live() -> None:
    import redis

    from attack_engine.eventbus.redis_bus import RedisStreamEventBus
    from attack_engine.schemas.events import Event, EventType

    client = redis.Redis.from_url(_REDIS_URL)
    bus = RedisStreamEventBus(client, stream_key="ae:it-test")
    bus.publish(Event(event=EventType.ASSET_DISCOVERED, engagement_id="eng-it",
                      emitted_by="test", target="10.5.0.10"))
    hist = bus.history(engagement_id="eng-it")
    assert any(e.event is EventType.ASSET_DISCOVERED for e in hist)
    bus.close()


# --- Neo4j graph backend ------------------------------------------------------

_NEO4J_URL = os.getenv("AE_TEST_NEO4J_URL")


@pytest.mark.skipif(not (_NEO4J_URL and _have("neo4j")), reason="no neo4j url/driver")
def test_neo4j_graph_live() -> None:
    from attack_engine.knowledge.neo4j_backend import Neo4jGraphBackend
    from attack_engine.schemas.findings import Asset, Service

    # The neo4j driver requires auth passed separately (not embedded in the URI).
    backend = Neo4jGraphBackend(
        url=_NEO4J_URL,
        user=os.getenv("AE_TEST_NEO4J_USER", "neo4j"),
        password=os.getenv("AE_TEST_NEO4J_PASSWORD"),
        engagement_id="eng-it",
    )
    backend.add_asset(Asset(id="a-it", address="10.5.0.10", engagement_id="eng-it",
                            services=(Service(port=80),)))
    assert backend.is_reachable("a-it")
    assert "a-it" in backend.reachable_assets()
    backend.close()
