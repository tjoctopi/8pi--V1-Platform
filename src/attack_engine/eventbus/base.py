"""Event bus interface.

The bus is intentionally small: publish an event, subscribe a callback to some
event types, and replay history for a late subscriber (the Orchestrator may
start after recon has already emitted). ``publish`` returns the stored event so
callers can chain (e.g. record its id).

Delivery is *at-least-once* and ordered per bus. Subscriber callbacks must be
idempotent — which fits the blackboard model, where re-processing an event is
safe because state lives in the knowledge store, not the handoff.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from typing import Protocol, runtime_checkable

from ..schemas.events import Event, EventType

EventHandler = Callable[[Event], None]


@runtime_checkable
class EventPublisher(Protocol):
    """Minimal structural type for anything a component can publish to.

    Components that only *emit* (Tool Runner, Knowledge Store, agents) depend on
    this narrow protocol rather than the full :class:`EventBus`, so they accept
    any publisher (including a test double) without importing the concrete bus.
    """

    def publish(self, event: Event) -> Event: ...


class Subscription:
    """Handle returned by :meth:`EventBus.subscribe`; call to unsubscribe."""

    def __init__(self, unsubscribe: Callable[[], None]) -> None:
        self._unsubscribe = unsubscribe
        self._active = True

    def cancel(self) -> None:
        if self._active:
            self._unsubscribe()
            self._active = False

    @property
    def active(self) -> bool:
        return self._active


class EventBus(ABC):
    """Abstract publish/subscribe bus over the blackboard event stream."""

    @abstractmethod
    def publish(self, event: Event) -> Event:
        """Persist and deliver ``event``. Returns the stored event."""

    @abstractmethod
    def subscribe(
        self,
        handler: EventHandler,
        *,
        event_types: Iterable[EventType] | None = None,
        engagement_id: str | None = None,
        replay: bool = False,
    ) -> Subscription:
        """Register ``handler``.

        ``event_types`` filters by type (``None`` = all — how Blue Sentry tails
        the whole run). ``engagement_id`` scopes to one engagement. ``replay``
        immediately re-delivers matching history before new events (for late
        subscribers).
        """

    @abstractmethod
    def history(
        self,
        *,
        engagement_id: str | None = None,
        event_types: Iterable[EventType] | None = None,
    ) -> list[Event]:
        """Return matching events in publication order."""

    @abstractmethod
    def close(self) -> None: ...
