"""Engagement-boundary authorization — the scanner→adversary shift.

A gated action can be resolved two ways: run it **autonomously** (because the
signed RoE pre-authorized it at the engagement boundary) or stop for a **human
gate**. :class:`AuthorizationPolicy` makes that call from the scope's RoE, and
:class:`KillSwitch` lets an approver halt an autonomous run instantly.

The design rule (from the offensive-platform strategy): move authorization to
the *engagement boundary*, then let agents run the full chain autonomously
*inside scope* — gating only a short, explicit high-impact list. Autonomy is
gated on a **signed, unexpired** scope; without that it fails safe to human
gates. Scope enforcement at the tool boundary is unaffected and non-negotiable.
"""

from __future__ import annotations

import threading
from datetime import datetime
from enum import Enum

from ..schemas.scope import Scope


class AuthorizationDecision(str, Enum):
    """How a controlled action is authorized."""

    #: Pre-authorized at the engagement boundary — run autonomously (audited).
    AUTONOMOUS = "autonomous"
    #: Requires an explicit human decision before proceeding.
    GATE = "gate"


class AuthorizationPolicy:
    """Decides autonomous-vs-gate for a *controlled* action, from the RoE.

    "Controlled" (is this action gated at all?) is decided by the caller from
    ``roe.gated_actions`` + the agent spec; this policy only answers, for an
    action already known to be controlled, whether the engagement's standing
    authorization covers it.
    """

    def __init__(self, scope: Scope) -> None:
        self._scope = scope
        self._roe = scope.roe

    def _authorized_engagement(self, now: datetime | None = None) -> bool:
        # Autonomy requires a real, signed, unexpired authorization — never on
        # an unsigned or lapsed scope (fail safe to gating).
        return self._scope.is_signed() and not self._scope.is_expired(now)

    def decide(
        self, action: str, technique: str | None = None, *, now: datetime | None = None
    ) -> AuthorizationDecision:
        roe = self._roe
        # Tier 0, or no valid signed authorization → gate everything controlled.
        if roe.autonomy_tier <= 0 or not self._authorized_engagement(now):
            return AuthorizationDecision.GATE
        # High-impact actions always gate, even when otherwise pre-authorized.
        if action in roe.high_impact_actions:
            return AuthorizationDecision.GATE
        # Explicitly pre-authorized (by action name or ATT&CK technique)?
        if action in roe.authorized_techniques:
            return AuthorizationDecision.AUTONOMOUS
        if technique is not None and technique in roe.authorized_techniques:
            return AuthorizationDecision.AUTONOMOUS
        # Anything off the allowlist gates — authorization is never implicit.
        return AuthorizationDecision.GATE


class KillSwitch:
    """A thread-safe engagement halt flag an approver can trip at any time.

    Agents check it before each controlled/aggressive step; once tripped, the
    engagement stops. It is the operator's instant off-switch for an autonomous
    run — a hard requirement for selling autonomy to regulated buyers.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tripped = False
        self._reason = ""
        self._by = ""

    def trip(self, reason: str = "operator halt", by: str = "operator") -> None:
        with self._lock:
            self._tripped = True
            self._reason = reason
            self._by = by

    @property
    def tripped(self) -> bool:
        with self._lock:
            return self._tripped

    @property
    def reason(self) -> str:
        with self._lock:
            return self._reason

    @property
    def tripped_by(self) -> str:
        with self._lock:
            return self._by
