"""Shared primitives for all schemas: ids, timestamps, base model."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict


def utcnow() -> datetime:
    """Timezone-aware UTC now. Single chokepoint so tests can freeze time."""

    return datetime.now(UTC)


def iso_now() -> str:
    """ISO-8601 UTC timestamp string (used in event/tool payloads)."""

    return utcnow().isoformat()


def new_id(prefix: str) -> str:
    """Short, prefixed, collision-resistant id, e.g. ``f-0a1b2c3d``.

    The prefix makes ids self-describing in logs and the audit trail
    (``f-`` finding, ``a-`` asset, ``eng-`` engagement, ...).
    """

    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class StrictModel(BaseModel):
    """Base for schemas: forbid unknown fields, validate on assignment.

    Rejecting extras is deliberate — a typo'd field in an agent spec or a
    tool's parsed output should fail loudly, not be silently dropped.
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        use_enum_values=False,
        ser_json_bytes="base64",
        val_json_bytes="base64",
    )
