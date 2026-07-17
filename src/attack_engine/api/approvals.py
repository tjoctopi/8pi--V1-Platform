"""Async human-approval broker — human gates over HTTP.

The engine consults a :data:`~attack_engine.governance.gates.Responder`
synchronously whenever an agent hits a gated (high-impact) action: the calling
worker thread blocks inside the responder until a decision comes back. In a CLI
that decision is a terminal prompt; here it is an operator clicking **Approve**
or **Deny** in the console.

:class:`ApprovalBroker` bridges the two. Its :meth:`responder` (handed to the
engine when an engagement opens) parks the request and blocks the worker thread
on an :class:`threading.Event`; the HTTP layer lists the parked requests
(:meth:`approvals`) and resolves one (:meth:`resolve`), which fires the event and
unblocks the engine. If no human answers within the timeout the request
**fails closed** (denied) — the system never proceeds on a gated action without
an explicit, in-time approval (rule #5).

Security note: this is a *transport* for a human decision, not a new authority.
Scope, the audit of the gate request/decision, and the deny-by-default posture
all still live in the engine's :class:`HumanGate`; the broker only carries the
answer back.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from ..governance.gates import GateDecision, GateRequest, GateResponse
from ..schemas.common import utcnow

#: How long a parked gate waits for a human before failing closed (denied).
DEFAULT_TIMEOUT_SEC = 900

#: How many resolved approvals to retain per engagement for the console history.
_HISTORY_CAP = 200


@dataclass
class _Pending:
    request: GateRequest
    event: threading.Event = field(default_factory=threading.Event)
    response: GateResponse | None = None


def _request_to_json(req: GateRequest, status: str, **extra: Any) -> dict[str, Any]:
    """Console-shaped approval row (matches ConsoleTab + Red Scope)."""

    ctx = req.context or {}
    technique = ctx.get("technique")
    return {
        "id": req.id,
        "engagement_id": req.engagement_id,
        "status": status,
        "gate": req.gate,
        "requested_by": req.requested_by,
        "created_at": req.ts,
        "action": {
            "tool_id": ctx.get("tool") or req.gate,
            "target": req.target,
            "rationale": req.summary or f"{req.gate} awaiting human approval",
            "technique": technique,
        },
        **extra,
    }


class ApprovalBroker:
    """Parks gated actions for human approval over HTTP; thread-safe."""

    def __init__(self, *, timeout_sec: int = DEFAULT_TIMEOUT_SEC) -> None:
        self._pending: dict[str, _Pending] = {}
        self._resolved: dict[str, list[dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self._timeout = timeout_sec

    # ── engine side (runs on the worker thread) ────────────────────────────
    def responder(self, req: GateRequest) -> GateResponse:
        """Block until a human resolves ``req`` (or the timeout denies it)."""

        pending = _Pending(request=req)
        with self._lock:
            self._pending[req.id] = pending
        answered = pending.event.wait(self._timeout)
        with self._lock:
            self._pending.pop(req.id, None)
            response = pending.response
        if not answered or response is None:
            response = GateResponse(
                decision=GateDecision.DENIED,
                reason="approval request timed out (failed closed)",
            )
        self._archive(req, response)
        return response

    # ── HTTP side ──────────────────────────────────────────────────────────
    def resolve(
        self,
        approval_id: str,
        *,
        approved: bool,
        approver: str,
        reason: str = "",
    ) -> bool:
        """Resolve a parked request. Returns False if it isn't pending (gone/timed out)."""

        with self._lock:
            pending = self._pending.get(approval_id)
            if pending is None:
                return False
            pending.response = GateResponse(
                decision=GateDecision.APPROVED if approved else GateDecision.DENIED,
                approver=approver,
                reason=reason,
            )
            pending.event.set()
        return True

    def pending(self, engagement_id: str) -> list[dict[str, Any]]:
        with self._lock:
            reqs = [
                p.request
                for p in self._pending.values()
                if p.request.engagement_id == engagement_id
            ]
        reqs.sort(key=lambda r: r.ts)
        return [_request_to_json(r, "pending") for r in reqs]

    def approvals(
        self, engagement_id: str, status: str | None = None
    ) -> list[dict[str, Any]]:
        """Pending + recently-resolved approvals for the console, newest first."""

        with self._lock:
            resolved = list(self._resolved.get(engagement_id, []))
        rows = self.pending(engagement_id) + list(reversed(resolved))
        if status:
            rows = [r for r in rows if r["status"] == status]
        return rows

    def pending_count(self, engagement_id: str) -> int:
        with self._lock:
            return sum(
                1
                for p in self._pending.values()
                if p.request.engagement_id == engagement_id
            )

    # ── internal ─────────────────────────────────────────────────────────────
    def _archive(self, req: GateRequest, response: GateResponse) -> None:
        status = "approved" if response.decision is GateDecision.APPROVED else "denied"
        row = _request_to_json(
            req,
            status,
            resolved_at=utcnow().isoformat(),
            approver=response.approver,
            reason=response.reason,
        )
        with self._lock:
            history = self._resolved.setdefault(req.engagement_id, [])
            history.append(row)
            if len(history) > _HISTORY_CAP:
                del history[: len(history) - _HISTORY_CAP]
