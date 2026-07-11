"""Shared pytest fixtures.

The whole suite runs with zero external services: audit → in-memory, event bus
→ in-memory, sandbox → noop, model → mock. Fixtures here centralise that so no
individual test reaches into the environment.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable, Iterator

import pytest

from attack_engine.schemas import RateLimit, RulesOfEngagement, Scope


@pytest.fixture
def engagement_id() -> str:
    return "eng-test-0001"


@pytest.fixture
def roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        read_only=True,
        default_rate_limit=RateLimit(requests_per_sec=100, burst=5),
    )


@pytest.fixture
def scope(engagement_id: str, roe: RulesOfEngagement) -> Scope:
    """A signed scope covering a small lab range + a couple of hosts."""

    return Scope(
        engagement_id=engagement_id,
        allowed_cidrs=("10.0.4.0/24", "192.168.56.0/24"),
        allowed_hosts=("juice.local", "target.range"),
        roe=roe,
        authorized_by="tester@8pi.ai",
        signature="test-signature",
    )


@pytest.fixture
def fake_clock() -> Callable[[], float]:
    """A manually-advanced monotonic clock for deterministic rate-limit tests."""

    state = {"t": 1000.0}

    def clock() -> float:
        return state["t"]

    clock.advance = lambda dt: state.__setitem__("t", state["t"] + dt)  # type: ignore[attr-defined]
    return clock


@pytest.fixture
def id_counter() -> Iterator[Callable[[], int]]:
    counter = itertools.count(1)
    yield lambda: next(counter)
