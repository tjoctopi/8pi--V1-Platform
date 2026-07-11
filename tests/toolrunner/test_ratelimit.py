"""Rate-limit tests — deterministic via an injected clock (no sleeps)."""

from __future__ import annotations

import pytest

from attack_engine.errors import RateLimitExceededError
from attack_engine.schemas import RateLimit, RulesOfEngagement, Scope
from attack_engine.toolrunner.ratelimit import RateLimiter


@pytest.fixture
def limited_scope() -> Scope:
    return Scope(
        engagement_id="eng-rl",
        allowed_cidrs=("10.0.4.0/24",),
        roe=RulesOfEngagement(default_rate_limit=RateLimit(requests_per_sec=2, burst=3)),
    )


def test_burst_then_block(limited_scope: Scope, fake_clock) -> None:
    rl = RateLimiter(limited_scope, clock=fake_clock)
    # burst=3 → first three succeed immediately
    assert rl.try_acquire("nmap", "10.0.4.12")
    assert rl.try_acquire("nmap", "10.0.4.12")
    assert rl.try_acquire("nmap", "10.0.4.12")
    # fourth blocked (bucket empty)
    assert not rl.try_acquire("nmap", "10.0.4.12")


def test_refill_over_time(limited_scope: Scope, fake_clock) -> None:
    rl = RateLimiter(limited_scope, clock=fake_clock)
    for _ in range(3):
        rl.try_acquire("nmap", "10.0.4.12")
    assert not rl.try_acquire("nmap", "10.0.4.12")
    # 2 req/sec → after 0.5s exactly one token returns
    fake_clock.advance(0.5)
    assert rl.try_acquire("nmap", "10.0.4.12")
    assert not rl.try_acquire("nmap", "10.0.4.12")


def test_buckets_are_per_tool_and_target(limited_scope: Scope, fake_clock) -> None:
    rl = RateLimiter(limited_scope, clock=fake_clock)
    for _ in range(3):
        rl.try_acquire("nmap", "10.0.4.12")
    # different target → fresh bucket
    assert rl.try_acquire("nmap", "10.0.4.13")
    # different tool, same target → fresh bucket
    assert rl.try_acquire("ffuf", "10.0.4.12")


def test_check_raises_with_details(limited_scope: Scope, fake_clock) -> None:
    rl = RateLimiter(limited_scope, clock=fake_clock)
    for _ in range(3):
        rl.check("nmap", "10.0.4.12")
    with pytest.raises(RateLimitExceededError) as ei:
        rl.check("nmap", "10.0.4.12")
    assert ei.value.tool == "nmap"
    assert ei.value.limit_per_sec == 2


def test_capacity_never_exceeds_burst(limited_scope: Scope, fake_clock) -> None:
    rl = RateLimiter(limited_scope, clock=fake_clock)
    # idle a long time; bucket must cap at burst=3, not accumulate unbounded
    fake_clock.advance(1000)
    acquired = sum(rl.try_acquire("nmap", "10.0.4.12") for _ in range(10))
    assert acquired == 3


def test_per_target_override(limited_scope: Scope, fake_clock) -> None:
    overrides = {"10.0.4.99": RateLimit(requests_per_sec=1, burst=1)}
    rl = RateLimiter(limited_scope, clock=fake_clock, overrides=overrides)
    assert rl.try_acquire("nmap", "10.0.4.99")
    assert not rl.try_acquire("nmap", "10.0.4.99")
