"""Blue Sentry tests — own-scan noise suppression + out-of-RoE alerting."""

from __future__ import annotations

import pytest

from attack_engine.defense.blue_sentry import BlueSentry
from attack_engine.eventbus.memory import InMemoryEventBus
from attack_engine.governance.audit import AuditLog
from attack_engine.schemas import Scope
from attack_engine.schemas.events import Event, EventType


@pytest.fixture
def scope() -> Scope:
    return Scope(engagement_id="engagement-range", allowed_cidrs=("10.5.0.0/24",),
                 authorized_by="t@8pi.ai", signature="sig")


@pytest.fixture
def audit() -> AuditLog:
    return AuditLog()


@pytest.fixture
def bus() -> InMemoryEventBus:
    return InMemoryEventBus()


def _emit(bus, etype, *, target=None, by="surface_mapper", payload=None):
    bus.publish(Event(event=etype, engagement_id="engagement-range", emitted_by=by,
                      target=target, payload=payload or {}))


def test_own_in_scope_scans_are_noise(scope, audit, bus) -> None:
    sentry = BlueSentry(scope, audit)
    sentry.attach(bus)
    _emit(bus, EventType.TOOL_STARTED, target="10.5.0.10")
    _emit(bus, EventType.TOOL_COMPLETED, target="10.5.0.10")
    _emit(bus, EventType.ASSET_DISCOVERED, target="10.5.0.10")
    assert sentry.report.expected_noise == 3
    assert sentry.report.alert_count == 0


def test_out_of_scope_target_raises_alert(scope, audit, bus) -> None:
    sentry = BlueSentry(scope, audit)
    sentry.attach(bus)
    _emit(bus, EventType.TOOL_COMPLETED, target="8.8.8.8")  # not in RoE
    assert sentry.report.alert_count == 1
    assert sentry.report.alerts[0].reason == "out_of_scope_target"
    assert "alert.raise" in [e.action for e in audit.entries()]


def test_scope_refusal_flags_out_of_roe_attempt(scope, audit, bus) -> None:
    sentry = BlueSentry(scope, audit)
    sentry.attach(bus)
    # An in-scope target string but a refusal for scope reasons (e.g. expired):
    _emit(bus, EventType.TOOL_REFUSED, target="10.5.0.10", by="toolrunner",
          payload={"reason": "scope"})
    assert sentry.report.alert_count == 1
    assert sentry.report.alerts[0].reason == "blocked_out_of_roe_attempt"


def test_alert_publishes_and_does_not_loop(scope, audit, bus) -> None:
    sentry = BlueSentry(scope, audit)
    sentry.attach(bus)
    alerts_seen = []
    bus.subscribe(lambda e: alerts_seen.append(e), event_types=[EventType.ALERT_RAISED])
    _emit(bus, EventType.TOOL_COMPLETED, target="8.8.8.8")
    # Exactly one alert emitted; Blue Sentry ignores its own ALERT_RAISED (no loop).
    assert len(alerts_seen) == 1
    assert sentry.report.alert_count == 1


def test_audit_chain_intact_after_alerts(scope, audit, bus) -> None:
    sentry = BlueSentry(scope, audit)
    sentry.attach(bus)
    _emit(bus, EventType.TOOL_COMPLETED, target="8.8.8.8")
    assert audit.verify() is True
