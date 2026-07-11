"""Redis Streams event bus (production blackboard).

Durable, tailable, cross-process. Every event is ``XADD``-ed to a per-engine
stream; history is an ``XRANGE`` scan; live subscribers run a background
consumer thread doing blocking ``XREAD`` from their last-seen id. This is the
"cheap, durable, easy to tail" bus the spec calls for, and it upgrades to NATS
later behind the same :class:`~attack_engine.eventbus.base.EventBus` interface.

The ``redis`` package is an optional dependency; importing this module without
it raises a clear error only when you actually try to construct the bus.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterable
from typing import Any

from ..logging import get_logger
from ..schemas.events import Event, EventType
from .base import EventBus, EventHandler, Subscription

_log = get_logger("eventbus.redis")

try:  # pragma: no cover - import guard
    import redis as _redis
except ImportError:  # pragma: no cover
    _redis = None  # type: ignore[assignment]


class RedisStreamEventBus(EventBus):
    """Event bus backed by a single Redis Stream.

    Parameters
    ----------
    client:
        A ``redis.Redis`` (or API-compatible, e.g. ``fakeredis``) instance.
    stream_key:
        The stream all events are appended to.
    poll_interval:
        Sleep between empty reads when the client's ``XREAD BLOCK`` returns
        without blocking (e.g. fakeredis).
    """

    def __init__(
        self,
        client: Any = None,
        *,
        url: str | None = None,
        stream_key: str = "ae:events",
        poll_interval: float = 0.05,
        block_ms: int = 200,
    ) -> None:
        if client is None:
            if _redis is None:
                raise RuntimeError(
                    "the 'redis' extra is not installed; "
                    "install attack-engine[redis] to use RedisStreamEventBus"
                )
            client = _redis.Redis.from_url(url or "redis://localhost:6379/0")
        self._r: Any = client
        self._key = stream_key
        self._poll = poll_interval
        self._block_ms = block_ms
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()

    def publish(self, event: Event) -> Event:
        self._r.xadd(self._key, {"data": event.model_dump_json()})
        return event

    @staticmethod
    def _decode(fields: dict[Any, Any]) -> Event:
        raw = fields.get(b"data", fields.get("data"))
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        if not isinstance(raw, str):
            raise ValueError("malformed stream entry: missing 'data' field")
        return Event.model_validate(json.loads(raw))

    def _matches(
        self,
        event: Event,
        types: frozenset[EventType] | None,
        engagement_id: str | None,
    ) -> bool:
        type_ok = types is None or event.event in types
        eng_ok = engagement_id is None or event.engagement_id == engagement_id
        return type_ok and eng_ok

    def history(
        self,
        *,
        engagement_id: str | None = None,
        event_types: Iterable[EventType] | None = None,
    ) -> list[Event]:
        types = frozenset(event_types) if event_types is not None else None
        raw_entries = self._r.xrange(self._key)
        out: list[Event] = []
        for _id, fields in raw_entries:
            event = self._decode(fields)
            if self._matches(event, types, engagement_id):
                out.append(event)
        return out

    def subscribe(
        self,
        handler: EventHandler,
        *,
        event_types: Iterable[EventType] | None = None,
        engagement_id: str | None = None,
        replay: bool = False,
    ) -> Subscription:
        types = frozenset(event_types) if event_types is not None else None
        # Resolve the starting cursor to a *concrete* id now, so polling clients
        # (e.g. fakeredis, which doesn't truly block on "$") don't perpetually
        # ask for "newer than latest" and miss everything. Replay starts at 0;
        # a live tail starts just after the current last id.
        if replay:
            start_id = "0"
        else:
            last = self._r.xrevrange(self._key, count=1)
            if last:
                last_entry_id = last[0][0]
                start_id = (
                    last_entry_id.decode()
                    if isinstance(last_entry_id, bytes)
                    else last_entry_id
                )
            else:
                start_id = "0"
        stop = threading.Event()

        def _consume() -> None:
            last_id = start_id
            while not stop.is_set() and not self._stop.is_set():
                try:
                    resp = self._r.xread(
                        {self._key: last_id}, block=self._block_ms, count=100
                    )
                except Exception:
                    _log.exception("redis xread failed")
                    time.sleep(self._poll)
                    continue
                if not resp:
                    time.sleep(self._poll)
                    continue
                for _stream, entries in resp:
                    for entry_id, fields in entries:
                        last_id = (
                            entry_id.decode() if isinstance(entry_id, bytes) else entry_id
                        )
                        event = self._decode(fields)
                        if self._matches(event, types, engagement_id):
                            try:
                                handler(event)
                            except Exception:
                                _log.exception("event handler raised")

        thread = threading.Thread(target=_consume, daemon=True, name="redis-eventbus-sub")
        thread.start()
        self._threads.append(thread)

        def _unsub() -> None:
            stop.set()
            thread.join(timeout=2.0)

        return Subscription(_unsub)

    def close(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=2.0)
