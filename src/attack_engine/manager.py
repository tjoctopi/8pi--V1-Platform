"""Multi-engagement manager with RBAC isolation (spec §9 Sprint 3).

A single deployment runs many engagements for many customers. This manager is
the access boundary between them: a :class:`~attack_engine.governance.rbac.Principal`
may only open, read, or manage engagements it is authorised for, and every
open/close is audited with the acting principal. Combined with the per-engagement
:class:`~attack_engine.knowledge.store.KnowledgeStore`, this gives hard tenant
isolation — one engagement can never read another's blackboard.

Gates for an engagement are wired to an RBAC-authorised *approver* principal
(segregation of duty), so the operator who runs the offense is not the person
who approves the real-world-effect actions.
"""

from __future__ import annotations

from .engine import Engagement, Engine
from .errors import AuthorizationError
from .governance.gates import rbac_responder
from .governance.rbac import AccessControl, Permission, Principal
from .logging import get_logger
from .schemas.scope import Scope

_log = get_logger("manager")


class EngagementManager:
    """Opens and isolates engagements behind RBAC."""

    def __init__(self, engine: Engine, *, access: AccessControl | None = None) -> None:
        self._engine = engine
        self._access = access or AccessControl()
        self._engagements: dict[str, Engagement] = {}

    @property
    def access(self) -> AccessControl:
        return self._access

    def open(
        self,
        scope: Scope,
        operator: Principal,
        *,
        approver: Principal | None = None,
        require_signed: bool | None = None,
    ) -> Engagement:
        """Open an engagement for ``operator`` (RBAC-checked, audited).

        ``operator`` must hold ``MANAGE_ENGAGEMENT`` and have access to the
        engagement id. If an ``approver`` principal is given, gates are wired to
        require *that* principal's authorised approval (segregation of duty).
        """

        self._access.check(
            operator, Permission.MANAGE_ENGAGEMENT, engagement_id=scope.engagement_id
        )
        responder = (
            rbac_responder(self._access, approver) if approver is not None else None
        )
        engagement = self._engine.engagement(
            scope, require_signed=require_signed, gate_responder=responder
        )
        self._engagements[scope.engagement_id] = engagement
        self._engine.audit.append(
            engagement_id=scope.engagement_id,
            actor=operator.id,
            action="engagement.open",
            payload={
                "operator": operator.id,
                "approver": approver.id if approver else None,
                "roles": sorted(r.value for r in operator.roles),
            },
        )
        _log.info("engagement opened", engagement=scope.engagement_id, operator=operator.id)
        return engagement

    def get(self, engagement_id: str, principal: Principal) -> Engagement:
        """Return an open engagement if ``principal`` may read it.

        Raises :class:`AuthorizationError` if the principal lacks read access —
        the isolation boundary: a principal never receives an engagement handle
        it isn't entitled to (even to observe).
        """

        self._access.check(principal, Permission.READ_FINDINGS, engagement_id=engagement_id)
        engagement = self._engagements.get(engagement_id)
        if engagement is None:
            raise AuthorizationError(
                principal.id, Permission.READ_FINDINGS.value,
                f"engagement {engagement_id!r} is not open",
            )
        return engagement

    def list_open(self, principal: Principal) -> list[str]:
        """Engagement ids that are open *and* this principal may access."""

        return [
            eid for eid in self._engagements
            if self._access.allows(principal, Permission.READ_FINDINGS, engagement_id=eid)
        ]

    def close(self, engagement_id: str, principal: Principal) -> None:
        self._access.check(
            principal, Permission.MANAGE_ENGAGEMENT, engagement_id=engagement_id
        )
        if self._engagements.pop(engagement_id, None) is not None:
            self._engine.audit.append(
                engagement_id=engagement_id,
                actor=principal.id,
                action="engagement.close",
                payload={"principal": principal.id},
            )
