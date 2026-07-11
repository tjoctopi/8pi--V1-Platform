"""Human-in-the-loop gates.

Anything with real-world effect — exploitation beyond confirmation, applying a
fix, containment — stops at a gate until a human approves. A gate request and
its decision are both audited, so the record shows *who* authorised *what*.

The :class:`HumanGate` is deliberately an interface with pluggable *responders*
so the same gate logic drives a CLI prompt, an approval queue, or (in tests) an
auto-approve/deny policy. Nothing about the decision is left to an agent.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from enum import Enum
from typing import TYPE_CHECKING, Any

from ..errors import GateDeniedError
from ..schemas.common import StrictModel, iso_now, new_id
from .audit import AuditLog

if TYPE_CHECKING:
    from .rbac import AccessControl, Principal


class GateDecision(str, Enum):
    APPROVED = "approved"
    DENIED = "denied"


class GateRequest(StrictModel):
    """A request for human authorisation of a gated action."""

    id: str
    engagement_id: str
    gate: str  # e.g. "exploit_confirm", "apply_fix", "containment"
    requested_by: str  # agent/component id
    target: str | None = None
    summary: str = ""
    context: dict[str, Any] = {}
    ts: str


#: A responder decides a request. Return APPROVED/DENIED (+ optional approver).
Responder = Callable[[GateRequest], "GateResponse"]


class GateResponse(StrictModel):
    decision: GateDecision
    approver: str | None = None
    reason: str = ""


class Gate(ABC):
    """Abstract gate. Implementations decide how a human is consulted."""

    @abstractmethod
    def request(self, req: GateRequest) -> GateResponse: ...


def deny_all(_req: GateRequest) -> GateResponse:
    """Fail-closed responder — the safe default when no human is wired up."""

    return GateResponse(decision=GateDecision.DENIED, reason="no approver configured")


class HumanGate(Gate):
    """Consults a responder, audits both request and decision, enforces deny.

    The responder is where the human actually lives (CLI prompt, web approval,
    ticket). If none is supplied, the gate fails closed (:func:`deny_all`) —
    the system never proceeds on a gated action without an explicit approval.
    """

    def __init__(self, audit: AuditLog, responder: Responder | None = None) -> None:
        self._audit = audit
        self._responder = responder or deny_all

    def build_request(
        self,
        *,
        engagement_id: str,
        gate: str,
        requested_by: str,
        target: str | None = None,
        summary: str = "",
        context: dict[str, Any] | None = None,
    ) -> GateRequest:
        return GateRequest(
            id=new_id("gate"),
            engagement_id=engagement_id,
            gate=gate,
            requested_by=requested_by,
            target=target,
            summary=summary,
            context=context or {},
            ts=iso_now(),
        )

    def request(self, req: GateRequest) -> GateResponse:
        self._audit.append(
            engagement_id=req.engagement_id,
            actor=req.requested_by,
            action="gate.request",
            target=req.target,
            payload={"gate": req.gate, "summary": req.summary, "request_id": req.id},
        )
        response = self._responder(req)
        self._audit.append(
            engagement_id=req.engagement_id,
            actor=response.approver or "human",
            action=f"gate.{response.decision.value}",
            target=req.target,
            payload={
                "gate": req.gate,
                "request_id": req.id,
                "reason": response.reason,
            },
        )
        return response

    def require(
        self,
        *,
        engagement_id: str,
        gate: str,
        requested_by: str,
        target: str | None = None,
        summary: str = "",
        context: dict[str, Any] | None = None,
    ) -> GateResponse:
        """Request approval; raise :class:`GateDeniedError` if not approved.

        Convenience for call sites that treat a denial as a hard stop (most of
        them). Returns the response on approval so the approver is recorded.
        """

        req = self.build_request(
            engagement_id=engagement_id,
            gate=gate,
            requested_by=requested_by,
            target=target,
            summary=summary,
            context=context,
        )
        response = self.request(req)
        if response.decision is not GateDecision.APPROVED:
            raise GateDeniedError(gate, response.reason or "denied")
        return response


def approve_all(approver: str = "test-approver") -> Responder:
    """Auto-approve responder — TESTS/DEV ONLY. Never wire in prod."""

    def _responder(_req: GateRequest) -> GateResponse:
        return GateResponse(decision=GateDecision.APPROVED, approver=approver)

    return _responder


def rbac_responder(
    access: AccessControl, approver_principal: Principal, *, inner: Responder | None = None
) -> Responder:
    """A responder that only honours approvals from an *authorised* approver.

    Enforces segregation of duty: the approving principal must hold
    ``APPROVE_GATE`` for the engagement, and ``apply_fix`` additionally requires
    ``APPLY_FIX``. If authorised, ``inner`` decides (default: approve); if not,
    the request is denied and the reason recorded. This is how RBAC composes
    with the human gate — RBAC gates *who may approve*, the gate records *the
    approval*.
    """

    from .rbac import Permission

    decide = inner or approve_all(approver_principal.id)

    def _responder(req: GateRequest) -> GateResponse:
        if not access.allows(
            approver_principal, Permission.APPROVE_GATE, engagement_id=req.engagement_id
        ):
            return GateResponse(
                decision=GateDecision.DENIED,
                approver=approver_principal.id,
                reason="approver not authorized to approve gates on this engagement",
            )
        if req.gate == "apply_fix" and not approver_principal.has(Permission.APPLY_FIX):
            return GateResponse(
                decision=GateDecision.DENIED,
                approver=approver_principal.id,
                reason="approver lacks apply_fix permission",
            )
        response = decide(req)
        # Stamp the authorised approver's identity onto the decision.
        return response.model_copy(update={"approver": approver_principal.id})

    return _responder
