"""Post-exploitation operator — governed actions on a live session (O3).

Runs post-access operations (host enumeration, an authorized command, bounded
pivot reconnaissance) against a session held by the :class:`SessionManager`,
through a :class:`~attack_engine.c2.backend.C2Backend`. Every action is:

* **authorized** — the same engagement-boundary policy as everything else
  (Tier ≥ 1 pre-authorizes ``post_exploitation`` → autonomous; else a human gate);
* **scope-bound** — the session's host (and any pivot target) must be in scope;
* **kill-switchable** and **fully audited**.

This is the operator layer the strategy calls for: "enumerate, collect, pivot on
authorized hosts." It weaponises the foothold — under authorization, never a
proof ceremony.
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
from ..toolrunner.scope import ScopeEnforcer
from .backend import C2Backend
from .session import Session, SessionManager

_log = get_logger("c2.postex")

#: Benign host-enumeration commands run on a foothold (Discovery — TA0007).
_ENUM_COMMANDS: tuple[str, ...] = (
    "id", "whoami", "hostname", "uname -a", "ip -o addr 2>/dev/null || ifconfig -a",
)
_POSTEX_ACTION = "post_exploitation"
_POSTEX_TECHNIQUE = "T1059"  # Command and Scripting Interpreter


@dataclass(frozen=True)
class PostExResult:
    action: str
    session_id: str
    host: str
    command: str
    output: str
    ok: bool = True


@dataclass
class PostExReport:
    results: list[PostExResult] = field(default_factory=list)
    gated_denied: int = 0


class PostExOperator:
    """Drives authorized, scope-bound, audited post-exploitation on a session."""

    def __init__(
        self,
        manager: SessionManager,
        backend: C2Backend,
        scope: Scope,
        audit: AuditLog,
        *,
        gate: HumanGate | None = None,
        kill_switch: KillSwitch | None = None,
        actor: str = "postex",
    ) -> None:
        self._mgr = manager
        self._backend = backend
        self._scope = scope
        self._audit = audit
        self._gate = gate
        self._kill = kill_switch
        self._enforcer = ScopeEnforcer(scope)
        self._actor = actor

    # --- governance -----------------------------------------------------------

    def _authorize(self, host: str, summary: str) -> None:
        """Authorize a post-ex action: autonomous (audited) or human gate."""

        if self._kill is not None and self._kill.tripped:
            raise StopConditionReached("kill_switch", self._kill.reason)
        decision = AuthorizationPolicy(self._scope).decide(_POSTEX_ACTION, _POSTEX_TECHNIQUE)
        if decision is AuthorizationDecision.AUTONOMOUS:
            self._audit.append(
                engagement_id=self._scope.engagement_id, actor=self._actor,
                action="action.authorized", target=host,
                payload={"action": _POSTEX_ACTION, "technique": _POSTEX_TECHNIQUE,
                         "autonomy_tier": self._scope.roe.autonomy_tier,
                         "basis": "engagement-boundary authorization", "summary": summary},
            )
            return
        if self._gate is None:
            raise StopConditionReached("gate_unavailable", _POSTEX_ACTION)
        self._gate.require(
            engagement_id=self._scope.engagement_id, gate=_POSTEX_ACTION,
            requested_by=self._actor, target=host, summary=summary,
        )

    def _exec(self, action: str, session: Session, command: str) -> PostExResult:
        output = self._backend.run_command(session, command)
        self._audit.append(
            engagement_id=self._scope.engagement_id, actor=self._actor,
            action="c2.postex", target=session.host,
            payload={"session_id": session.id, "postex": action, "command": command},
        )
        return PostExResult(action=action, session_id=session.id, host=session.host,
                            command=command, output=output)

    # --- operations -----------------------------------------------------------

    def enumerate(self, session: Session) -> PostExReport:
        """Run benign host enumeration on the foothold (who/where/what am I)."""

        report = PostExReport()
        try:
            self._authorize(session.host, f"enumerate host via session {session.id}")
        except GateDeniedError:
            report.gated_denied += 1
            return report
        if not self._backend.alive(session):
            return report
        for cmd in _ENUM_COMMANDS:
            report.results.append(self._exec("enumerate", session, cmd))
        _log.info("post-ex enumerate", session=session.id, host=session.host)
        return report

    def run(self, session: Session, command: str) -> PostExResult | None:
        """Run a single authorized command on the session."""

        try:
            self._authorize(session.host, f"run '{command}' via session {session.id}")
        except GateDeniedError:
            return None
        if not self._backend.alive(session):
            return None
        return self._exec("run", session, command)

    def pivot_recon(self, session: Session, target: str) -> PostExResult | None:
        """Discover an internal host *through* the foothold (bounded recon).

        Scope-checks the pivot target first — lateral reconnaissance stays inside
        the authorized estate. Establishing a session on the new host is lateral
        movement (O5/O6); here we only look.
        """

        self._enforcer.check(target)  # OOS pivot target refused (audited by caller)
        try:
            self._authorize(session.host, f"pivot recon {target} via session {session.id}")
        except GateDeniedError:
            return None
        if not self._backend.alive(session):
            return None
        # A bounded reachability probe from the foothold toward the internal host.
        cmd = f"(command -v nc && nc -z -w2 {target} 22 445 3389) || ping -c1 -W2 {target}"
        result = self._exec("pivot_recon", session, cmd)
        self._audit.append(
            engagement_id=self._scope.engagement_id, actor=self._actor,
            action="c2.pivot", target=target,
            payload={"session_id": session.id, "from_host": session.host},
        )
        return result
