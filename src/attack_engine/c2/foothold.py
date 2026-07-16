"""Foothold lifecycle — turning a landed exploit into a live, proven session (O2→O3).

This closes the seam the platform was missing: exploitation that yields access
must actually *register a live session* and *prove* it, not detect a string and
throw the shell away. Given a host and a :class:`~attack_engine.c2.backend.C2Backend`
(the real transport — msfrpc/Sliver in prod, a mock in tests), the
:class:`FootholdRunner`:

    1. **authorizes** — establishing a real foothold is high-impact: Tier ≥ 1 on a
       signed scope may pre-authorize it (audited); otherwise it blocks on a human
       gate. Kill-switch honoured.
    2. **opens** a scope-checked, audited session in the SessionManager.
    3. **proves impact** — runs a bounded proof set (``whoami``/``hostname``/``id``)
       over the session and records the output as evidence (proof of a real shell,
       not a claim).
    4. is **kill-switchable** — :meth:`teardown` closes every live session's
       bookkeeping *and* its underlying transport.

This is real weaponisation, held inside the safety envelope: signed scope,
authorization gate, audit, kill switch. No data is exfiltrated — the proof reads
identity/host only.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..errors import GateDeniedError, StopConditionReached
from ..governance.audit import AuditLog
from ..governance.authorization import (
    AuthorizationDecision,
    AuthorizationPolicy,
    KillSwitch,
)
from ..governance.gates import HumanGate
from ..logging import get_logger
from ..schemas.scope import Scope
from .backend import C2Backend
from .session import Session, SessionKind, SessionManager

_log = get_logger("c2.foothold")

_ESTABLISH_ACTION = "establish_foothold"
#: Bounded proof-of-impact — identity/host only, never target data.
_PROOF_COMMANDS: tuple[str, ...] = ("id", "whoami", "hostname")


@dataclass
class Foothold:
    """A registered live session plus the proof it is real."""

    session: Session
    ok: bool
    proof: dict[str, str] = field(default_factory=dict)
    evidence: tuple[str, ...] = ()


class FootholdRunner:
    """Establishes, proves, and tears down live footholds — governed + audited."""

    def __init__(
        self,
        manager: SessionManager,
        backend: C2Backend,
        scope: Scope,
        audit: AuditLog,
        *,
        gate: HumanGate | None = None,
        kill_switch: KillSwitch | None = None,
        actor: str = "foothold",
    ) -> None:
        self._mgr = manager
        self._backend = backend
        self._scope = scope
        self._audit = audit
        self._gate = gate
        self._kill = kill_switch
        self._actor = actor

    def establish(
        self,
        host: str,
        *,
        kind: SessionKind = SessionKind.SHELL,
        opened_by: str = "",
        listener_id: str | None = None,
        technique: str = "T1190",
        metadata: dict[str, str] | None = None,
    ) -> Foothold | None:
        """Open and prove a live session on ``host``. None if the gate denies it.

        Raises ``ScopeViolationError`` (from the SessionManager) for an
        out-of-scope host and ``StopConditionReached`` if the kill switch is set —
        both expected, audited control flow.
        """

        try:
            self._authorize(host, technique)
        except GateDeniedError:
            self._audit.append(
                engagement_id=self._scope.engagement_id, actor=self._actor,
                action="c2.foothold.denied", target=host,
                payload={"action": _ESTABLISH_ACTION},
            )
            _log.warning("foothold gate denied", host=host)
            return None

        session = self._mgr.open_session(
            host, kind=kind, opened_by=opened_by or self._actor, listener_id=listener_id,
            metadata=metadata,
        )
        if not self._backend.alive(session):
            self._audit.append(
                engagement_id=self._scope.engagement_id, actor=self._actor,
                action="c2.foothold.dead", target=host,
                payload={"session_id": session.id},
            )
            _log.warning("foothold not alive", session=session.id, host=host)
            return Foothold(session=session, ok=False)

        proof, evidence = self._prove(session)
        _log.info("foothold established", session=session.id, host=host,
                  user=proof.get("whoami", "?"))
        return Foothold(session=session, ok=True, proof=proof, evidence=tuple(evidence))

    def teardown(self) -> int:
        """Close every active session's bookkeeping AND its transport (kill switch)."""

        active = self._mgr.sessions(active_only=True)
        for s in active:
            self._backend.close(s)
            self._mgr.close_session(s.id)
        if active:
            _log.info("footholds torn down", count=len(active))
        return len(active)

    # --- internals ------------------------------------------------------------

    def _authorize(self, host: str, technique: str) -> None:
        if self._kill is not None and self._kill.tripped:
            raise StopConditionReached("kill_switch", self._kill.reason)
        decision = AuthorizationPolicy(self._scope).decide(_ESTABLISH_ACTION, technique or None)
        if decision is AuthorizationDecision.AUTONOMOUS:
            self._audit.append(
                engagement_id=self._scope.engagement_id, actor=self._actor,
                action="action.authorized", target=host,
                payload={"action": _ESTABLISH_ACTION, "technique": technique,
                         "autonomy_tier": self._scope.roe.autonomy_tier,
                         "basis": "engagement-boundary authorization"},
            )
            return
        if self._gate is None:
            raise StopConditionReached("gate_unavailable", _ESTABLISH_ACTION)
        self._gate.require(
            engagement_id=self._scope.engagement_id, gate=_ESTABLISH_ACTION,
            requested_by=self._actor, target=host,
            summary=f"establish a live foothold on {host}",
        )

    def _prove(self, session: Session) -> tuple[dict[str, str], list[str]]:
        proof: dict[str, str] = {}
        evidence: list[str] = []
        for cmd in _PROOF_COMMANDS:
            output = self._backend.run_command(session, cmd).strip()
            proof[cmd] = output
            entry = self._audit.append(
                engagement_id=self._scope.engagement_id, actor=self._actor,
                action="c2.foothold.proof", target=session.host,
                payload={"session_id": session.id, "command": cmd, "output": output},
            )
            evidence.append(f"raw:{entry.entry_hash}")
        return proof, evidence
