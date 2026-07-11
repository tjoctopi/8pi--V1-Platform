"""AgentContext — the dependencies an agent is handed to do its job.

Agents are declarative (the :class:`~attack_engine.schemas.agentspec.AgentSpec`)
plus this bundle of shared services. Nothing is constructed inside an agent;
everything — the scope-enforcing Tool Runner, the blackboard, the model gateway,
the audit log — is injected, which is what makes agents unit-testable and keeps
the four rules enforced by the surrounding machinery rather than by the agent.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..eventbus.base import EventPublisher
from ..gateway.router import ModelGateway
from ..governance.audit import AuditLog
from ..governance.gates import HumanGate
from ..knowledge.store import KnowledgeStore
from ..schemas.scope import Scope
from ..toolrunner.runner import ToolRunner


@dataclass
class AgentContext:
    """Shared services for one engagement, handed to every agent."""

    scope: Scope
    tool_runner: ToolRunner
    store: KnowledgeStore
    audit: AuditLog
    gateway: ModelGateway | None = None
    event_bus: EventPublisher | None = None
    #: Human-in-the-loop gate. Required for any agent that performs a gated
    #: action (exploit-confirm, apply-fix, containment); absent for read-only
    #: agents. When a gated action is attempted without a gate, the agent fails
    #: closed.
    gate: HumanGate | None = None

    @property
    def engagement_id(self) -> str:
        return self.scope.engagement_id
