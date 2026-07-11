"""Event bus tests — in-memory (synchronous) and Redis Streams (via fakeredis)."""

from __future__ import annotations

import time
from collections.abc import Callable

import pytest

from attack_engine.eventbus.base import EventBus
from attack_engine.eventbus.memory import InMemoryEventBus
from attack_engine.schemas.events import Event, EventType


def make_event(engagement: str = "eng-1", etype: EventType = EventType.ASSET_DISCOVERED,
               by: str = "mapper") -> Event:
    return Event(event=etype, engagement_id=engagement, emitted_by=by)


def wait_for(predicate: Callable[[], bool], timeout: float = 2.0) -> bool:
    """Poll ``predicate`` until true or timeout. Used for async Redis delivery."""

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


# --- In-memory (fully synchronous, deterministic) -----------------------------


class TestInMemoryBus:
    def test_publish_returns_event_and_records_history(self) -> None:
        bus = InMemoryEventBus()
        e = bus.publish(make_event())
        assert e.event is EventType.ASSET_DISCOVERED
        assert len(bus.history(engagement_id="eng-1")) == 1

    def test_subscriber_receives_matching_events(self) -> None:
        bus = InMemoryEventBus()
        received: list[Event] = []
        bus.subscribe(received.append, event_types=[EventType.FINDING_CONFIRMED])
        bus.publish(make_event(etype=EventType.ASSET_DISCOVERED))  # filtered out
        bus.publish(make_event(etype=EventType.FINDING_CONFIRMED))
        assert len(received) == 1
        assert received[0].event is EventType.FINDING_CONFIRMED

    def test_blue_sentry_tails_all_events(self) -> None:
        bus = InMemoryEventBus()
        seen: list[EventType] = []
        bus.subscribe(lambda e: seen.append(e.event))  # no filter = everything
        bus.publish(make_event(etype=EventType.TOOL_STARTED))
        bus.publish(make_event(etype=EventType.TOOL_COMPLETED))
        bus.publish(make_event(etype=EventType.ALERT_RAISED))
        assert seen == [
            EventType.TOOL_STARTED,
            EventType.TOOL_COMPLETED,
            EventType.ALERT_RAISED,
        ]

    def test_engagement_scoping(self) -> None:
        bus = InMemoryEventBus()
        got: list[Event] = []
        bus.subscribe(got.append, engagement_id="eng-1")
        bus.publish(make_event(engagement="eng-1"))
        bus.publish(make_event(engagement="eng-2"))
        assert len(got) == 1

    def test_replay_for_late_subscriber(self) -> None:
        bus = InMemoryEventBus()
        bus.publish(make_event(etype=EventType.ASSET_DISCOVERED))
        bus.publish(make_event(etype=EventType.SERVICE_DISCOVERED))
        replayed: list[Event] = []
        bus.subscribe(replayed.append, replay=True)
        assert len(replayed) == 2

    def test_unsubscribe_stops_delivery(self) -> None:
        bus = InMemoryEventBus()
        got: list[Event] = []
        sub = bus.subscribe(got.append)
        bus.publish(make_event())
        sub.cancel()
        bus.publish(make_event())
        assert len(got) == 1
        assert not sub.active

    def test_bad_subscriber_does_not_break_bus(self) -> None:
        bus = InMemoryEventBus()
        good: list[Event] = []

        def boom(_e: Event) -> None:
            raise RuntimeError("subscriber blew up")

        bus.subscribe(boom)
        bus.subscribe(good.append)
        bus.publish(make_event())  # must not raise
        assert len(good) == 1


# --- Redis Streams (fakeredis, async delivery) --------------------------------

fakeredis = pytest.importorskip("fakeredis")


@pytest.fixture
def redis_bus() -> EventBus:
    from attack_engine.eventbus.redis_bus import RedisStreamEventBus

    client = fakeredis.FakeStrictRedis()
    bus = RedisStreamEventBus(client, stream_key="ae:test", poll_interval=0.01, block_ms=10)
    yield bus
    bus.close()


class TestRedisStreamBus:
    def test_publish_and_history(self, redis_bus: EventBus) -> None:
        redis_bus.publish(make_event(etype=EventType.ASSET_DISCOVERED))
        redis_bus.publish(make_event(etype=EventType.FINDING_CONFIRMED))
        hist = redis_bus.history(engagement_id="eng-1")
        assert [e.event for e in hist] == [
            EventType.ASSET_DISCOVERED,
            EventType.FINDING_CONFIRMED,
        ]

    def test_history_type_filter(self, redis_bus: EventBus) -> None:
        redis_bus.publish(make_event(etype=EventType.ASSET_DISCOVERED))
        redis_bus.publish(make_event(etype=EventType.FINDING_CONFIRMED))
        hist = redis_bus.history(event_types=[EventType.FINDING_CONFIRMED])
        assert len(hist) == 1

    def test_live_subscriber_receives_new_events(self, redis_bus: EventBus) -> None:
        received: list[Event] = []
        redis_bus.subscribe(received.append, event_types=[EventType.FINDING_CONFIRMED])
        redis_bus.publish(make_event(etype=EventType.FINDING_CONFIRMED))
        assert wait_for(lambda: len(received) == 1)

    def test_replay_reads_history(self, redis_bus: EventBus) -> None:
        redis_bus.publish(make_event(etype=EventType.ASSET_DISCOVERED))
        redis_bus.publish(make_event(etype=EventType.SERVICE_DISCOVERED))
        received: list[Event] = []
        redis_bus.subscribe(received.append, replay=True)
        assert wait_for(lambda: len(received) == 2)
