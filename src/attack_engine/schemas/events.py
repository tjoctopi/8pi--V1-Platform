"""Blackboard events — how agents coordinate without calling each other.

Agents never invoke one another directly. They publish typed events to the
event bus; the Orchestrator subscribes and decides the next dispatch, and the
Blue Sentry tails *every* event. This indirection is what makes the loop
robust: any agent can crash and be retried, and parallel agents can't corrupt
a linear handoff.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import Field

from .common import StrictModel, iso_now, new_id


class EventType(str, Enum):
    # engagement lifecycle
    ENGAGEMENT_STARTED = "engagement.started"
    ENGAGEMENT_CLOSED = "engagement.closed"
    # recon / assets
    ASSET_DISCOVERED = "asset.discovered"
    SERVICE_DISCOVERED = "service.discovered"
    # findings (propose/verify lifecycle mirrors FindingState)
    FINDING_PROPOSED = "finding.proposed"
    FINDING_VERIFIED = "finding.verified"
    FINDING_CONFIRMED = "finding.confirmed"
    FINDING_REJECTED = "finding.rejected"
    # tool runner
    TOOL_STARTED = "tool.started"
    TOOL_COMPLETED = "tool.completed"
    TOOL_REFUSED = "tool.refused"  # scope/rate/RoE refusal
    # agent runtime
    AGENT_STARTED = "agent.started"
    AGENT_STOPPED = "agent.stopped"
    # governance
    GATE_REQUESTED = "gate.requested"
    GATE_APPROVED = "gate.approved"
    GATE_DENIED = "gate.denied"
    # remediation + close-the-loop (spec §3 steps 6–7)
    REMEDIATION_PROPOSED = "remediation.proposed"
    FIX_APPLIED = "fix.applied"
    RETEST_PASSED = "retest.passed"
    RETEST_FAILED = "retest.failed"
    FINDING_ESCALATED = "finding.escalated"
    REPORT_GENERATED = "report.generated"
    # orchestration
    PHASE_STARTED = "phase.started"
    PHASE_COMPLETED = "phase.completed"
    # defensive
    ALERT_RAISED = "alert.raised"


class Event(StrictModel):
    """A single blackboard event. Immutable once published."""

    id: str = Field(default_factory=lambda: new_id("evt"))
    event: EventType
    engagement_id: str
    emitted_by: str  # agent id / component name
    ts: str = Field(default_factory=iso_now)

    # optional correlation ids
    finding_id: str | None = None
    asset_id: str | None = None
    audit_id: str | None = None
    target: str | None = None  # IP/host a tool event concerns

    #: Does acting on this event require a human gate?
    gate_required: bool = False

    #: Free-form structured payload (validated by consumers as needed).
    payload: dict[str, Any] = Field(default_factory=dict)

    def topic(self) -> str:
        """Stable topic string used by bus backends for routing/streams."""

        return self.event.value
