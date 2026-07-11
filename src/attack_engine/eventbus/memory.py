"""In-memory event bus.

Synchronous, ordered, single-process. Delivery happens inline on ``publish``
so tests are deterministic (no threads, no polling). History is retained so
late subscribers can replay — mirroring the durability Redis Streams gives us
in production without needing a server.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable

from ..logging import get_logger
from ..schemas.events import Event, EventType
from .base import EventBus, EventHandler, Subscription

_log = get_logger("eventbus.memory")


class _Sub:
    __slots__ = ("engagement_id", "event_types", "handler")

    def __init__(
        self,
        handler: EventHandler,
        event_types: frozenset[EventType] | None,
        engagement_id: str | None,
    ) -> None:
        self.handler = handler
        self.event_types = event_types
        self.engagement_id = engagement_id

    def matches(self, event: Event) -> bool:
        type_ok = self.event_types is None or event.event in self.event_types
        eng_ok = self.engagement_id is None or event.engagement_id == self.engagement_id
        return type_ok and eng_ok


class InMemoryEventBus(EventBus):
    def __init__(self) -> None:
        self._subs: list[_Sub] = []
        self._history: list[Event] = []
        self._lock = threading.RLock()

    def publish(self, event: Event) -> Event:
        with self._lock:
            self._history.append(event)
            subs = list(self._subs)
        # Deliver outside the lock so a handler that publishes won't deadlock.
        for sub in subs:
            if sub.matches(event):
                self._safe_deliver(sub, event)
        return event

    def _safe_deliver(self, sub: _Sub, event: Event) -> None:
        try:
            sub.handler(event)
        except Exception:
            _log.exception(
                "event handler raised",
                event_type=event.event.value,
                engagement=event.engagement_id,
            )

    def subscribe(
        self,
        handler: EventHandler,
        *,
        event_types: Iterable[EventType] | None = None,
        engagement_id: str | None = None,
        replay: bool = False,
    ) -> Subscription:
        types = frozenset(event_types) if event_types is not None else None
        sub = _Sub(handler, types, engagement_id)
        with self._lock:
            self._subs.append(sub)
            past = list(self._history) if replay else []

        for event in past:
            if sub.matches(event):
                self._safe_deliver(sub, event)

        def _unsub() -> None:
            with self._lock:
                if sub in self._subs:
                    self._subs.remove(sub)

        return Subscription(_unsub)

    def history(
        self,
        *,
        engagement_id: str | None = None,
        event_types: Iterable[EventType] | None = None,
    ) -> list[Event]:
        types = frozenset(event_types) if event_types is not None else None
        with self._lock:
            snapshot = list(self._history)
        return [
            e
            for e in snapshot
            if (engagement_id is None or e.engagement_id == engagement_id)
            and (types is None or e.event in types)
        ]

    def close(self) -> None:
        with self._lock:
            self._subs.clear()
