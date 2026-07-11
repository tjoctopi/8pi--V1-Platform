"""Event bus / blackboard — how agents coordinate (spec §2, §7).

Agents publish typed :class:`~attack_engine.schemas.events.Event`s; the
Orchestrator subscribes to decide the next dispatch and the Blue Sentry tails
*everything*. Backends are pluggable: an in-memory bus for tests/single-process
runs, and Redis Streams for durable, tailable cross-process coordination.
"""

from __future__ import annotations

from .base import EventBus, EventPublisher, Subscription
from .factory import build_event_bus
from .memory import InMemoryEventBus

__all__ = [
    "EventBus",
    "EventPublisher",
    "InMemoryEventBus",
    "Subscription",
    "build_event_bus",
]
