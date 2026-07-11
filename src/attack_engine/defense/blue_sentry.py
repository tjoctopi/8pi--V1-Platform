"""Blue Sentry — defensive triage, in parallel (spec §3, agent #7).

The Blue Sentry tails the event bus for the *whole* run. It does two jobs:

* **Noise suppression.** The engine's own authorized, in-scope activity is
  classified as *expected* — so a real SIEM/AI-SPM feed wouldn't drown a analyst
  in alerts about scans they authorised (alert fatigue is a real defensive
  failure mode).
* **Out-of-RoE detection.** Anything that falls outside the signed scope — a
  tool refusal for an out-of-scope target, or any event whose target isn't on
  the allowlist — is raised as an alert with evidence.

It observes and proposes; it does not act. Containment would be a separate,
gated action. Running it alongside the offensive loop is the offense+defense
loop proving itself on every engagement.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..eventbus.base import EventPublisher
from ..governance.audit import AuditLog
from ..logging import get_logger
from ..schemas.events import Event, EventType
from ..schemas.scope import Scope
from ..toolrunner.scope import ScopeEnforcer

_log = get_logger("defense.blue_sentry")

#: Event types that are normal, expected engine activity (suppressed as noise).
_EXPECTED = {
    EventType.ENGAGEMENT_STARTED, EventType.ENGAGEMENT_CLOSED,
    EventType.ASSET_DISCOVERED, EventType.SERVICE_DISCOVERED,
    EventType.FINDING_PROPOSED, EventType.FINDING_VERIFIED,
    EventType.FINDING_CONFIRMED, EventType.FINDING_REJECTED,
    EventType.TOOL_STARTED, EventType.TOOL_COMPLETED,
    EventType.AGENT_STARTED, EventType.AGENT_STOPPED,
    EventType.GATE_REQUESTED, EventType.GATE_APPROVED, EventType.GATE_DENIED,
    EventType.REMEDIATION_PROPOSED, EventType.FIX_APPLIED,
    EventType.RETEST_PASSED, EventType.RETEST_FAILED,
    EventType.FINDING_ESCALATED, EventType.REPORT_GENERATED,
    EventType.PHASE_STARTED, EventType.PHASE_COMPLETED,
}

_ACTOR = "blue_sentry"


@dataclass
class Alert:
    reason: str
    event_type: str
    target: str | None
    audit_id: str | None
    detail: str = ""


@dataclass
class SentryReport:
    expected_noise: int = 0
    alerts: list[Alert] = field(default_factory=list)

    @property
    def alert_count(self) -> int:
        return len(self.alerts)


class BlueSentry:
    """Passive event-bus observer: suppresses own-scan noise, flags out-of-RoE."""

    def __init__(self, scope: Scope, audit: AuditLog) -> None:
        self._scope = scope
        self._enforcer = ScopeEnforcer(scope)
        self._audit = audit
        self._bus: EventPublisher | None = None
        self.report = SentryReport()

    def attach(self, bus: object) -> None:
        """Subscribe to every event for this engagement.

        ``bus`` must support ``subscribe(handler, engagement_id=...)`` — the
        full :class:`~attack_engine.eventbus.base.EventBus`, not just a
        publisher (Blue Sentry needs to consume, and also to publish alerts).
        """

        self._bus = bus  # type: ignore[assignment]
        bus.subscribe(  # type: ignore[attr-defined]
            self._on_event, engagement_id=self._scope.engagement_id
        )

    def _on_event(self, event: Event) -> None:
        # Never react to our own alerts (no feedback loop).
        if event.emitted_by == _ACTOR or event.event is EventType.ALERT_RAISED:
            return

        # Out-of-scope target on any event → out-of-RoE activity.
        if event.target and not self._enforcer.allows(event.target):
            self._raise("out_of_scope_target", event, f"target {event.target!r} not in RoE")
            return

        # A scope/RoE refusal means something *tried* to leave bounds.
        if event.event is EventType.TOOL_REFUSED:
            reason = str(event.payload.get("reason", ""))
            if reason in ("scope", "forbidden_tool", "read_only"):
                self._raise("blocked_out_of_roe_attempt", event,
                            f"tool runner refused: {reason}")
                return

        if event.event in _EXPECTED:
            self.report.expected_noise += 1  # authorised, in-scope → noise
            return

        # Anything unrecognised is worth a human's eyes.
        self._raise("unclassified_activity", event, f"unexpected event {event.event.value}")

    def _raise(self, reason: str, event: Event, detail: str) -> None:
        entry = self._audit.append(
            engagement_id=self._scope.engagement_id,
            actor=_ACTOR,
            action="alert.raise",
            target=event.target,
            payload={"reason": reason, "source_event": event.event.value, "detail": detail},
        )
        alert = Alert(
            reason=reason,
            event_type=event.event.value,
            target=event.target,
            audit_id=entry.entry_hash,
            detail=detail,
        )
        self.report.alerts.append(alert)
        if self._bus is not None:
            self._bus.publish(
                Event(
                    event=EventType.ALERT_RAISED,
                    engagement_id=self._scope.engagement_id,
                    emitted_by=_ACTOR,
                    target=event.target,
                    audit_id=entry.entry_hash,
                    payload={"reason": reason, "detail": detail},
                )
            )
        _log.warning("blue sentry alert", reason=reason, target=event.target)
