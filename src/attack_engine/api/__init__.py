"""HTTP API layer over the engine.

This package is the "future API server" the composition root (``engine.py``)
was designed for: it wraps the process-wide :class:`~attack_engine.engine.Engine`
and the multi-tenant :class:`~attack_engine.manager.EngagementManager` behind an
HTTP contract, translating the engine's pydantic domain objects into the exact
JSON shapes the 8π console (``frontend/``) already consumes.

Nothing here re-implements security: scope enforcement, gates, the kill switch
and the hash-chained audit log all stay in the engine. This layer only *exposes*
them. It adds no external-service dependency of its own — with the engine's
default test/dev settings it runs entirely in-process (memory audit + event bus,
noop sandbox, mock model), consistent with the engine's zero-external-services
principle.

Install with the ``api`` extra (``pip install -e '.[api]'``) for FastAPI/uvicorn.
"""

from __future__ import annotations

from .adapter import EngineAdapter, engagement_id_for
from .serialize import (
    asset_to_json,
    audit_entry_to_json,
    finding_to_json,
    service_to_json,
)

__all__ = [
    "EngineAdapter",
    "engagement_id_for",
    "asset_to_json",
    "audit_entry_to_json",
    "finding_to_json",
    "service_to_json",
]
