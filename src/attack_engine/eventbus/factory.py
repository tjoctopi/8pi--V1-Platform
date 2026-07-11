"""Build the configured event bus from settings."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import EventBus
from .memory import InMemoryEventBus

if TYPE_CHECKING:
    from ..config import Settings


def build_event_bus(settings: Settings | None = None) -> EventBus:
    from ..config import EventBusBackend, get_settings

    s = settings or get_settings()
    if s.eventbus_backend is EventBusBackend.MEMORY:
        return InMemoryEventBus()
    if s.eventbus_backend is EventBusBackend.REDIS:
        from .redis_bus import RedisStreamEventBus

        return RedisStreamEventBus(
            url=s.eventbus_redis_url, stream_key=s.eventbus_stream_prefix
        )
    raise NotImplementedError(f"event bus backend {s.eventbus_backend!r} unavailable")
