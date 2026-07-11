"""Role-based access control (spec §9 Sprint 3 — "multi-engagement + RBAC").

Regulated buyers require that *who* did *what* is authorised and provable. RBAC
answers "may this principal perform this action on this engagement?" and every
decision is auditable. It composes with — never replaces — the RoE gate: RBAC
says *who is allowed to try*, the human gate says *this specific action is
approved*, and scope enforcement says *this target is in bounds*.

Roles are coarse and least-privilege by default; permissions are fine-grained so
new capabilities slot in without widening a role unintentionally.
"""

from __future__ import annotations

from enum import Enum

from ..errors import AuthorizationError
from ..schemas.common import StrictModel


class Permission(str, Enum):
    READ_FINDINGS = "read_findings"
    RUN_RECON = "run_recon"
    RUN_WEB = "run_web"
    RUN_EXPLOIT_CONFIRM = "run_exploit_confirm"
    APPROVE_GATE = "approve_gate"
    APPLY_FIX = "apply_fix"
    MANAGE_ENGAGEMENT = "manage_engagement"


class Role(str, Enum):
    VIEWER = "viewer"          # read-only access to results
    OPERATOR = "operator"      # runs the safe/offensive tooling
    APPROVER = "approver"      # approves human gates (segregation of duty)
    ADMIN = "admin"            # everything, incl. engagement management


_ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset({Permission.READ_FINDINGS}),
    Role.OPERATOR: frozenset(
        {
            Permission.READ_FINDINGS,
            Permission.RUN_RECON,
            Permission.RUN_WEB,
            Permission.RUN_EXPLOIT_CONFIRM,
        }
    ),
    # Segregation of duty: an approver approves but does not run offense.
    Role.APPROVER: frozenset(
        {Permission.READ_FINDINGS, Permission.APPROVE_GATE, Permission.APPLY_FIX}
    ),
    Role.ADMIN: frozenset(Permission),
}


class Principal(StrictModel):
    """An authenticated actor: an identity, its roles, and its engagement scope."""

    id: str  # e.g. an email or service-account id
    roles: frozenset[Role] = frozenset()
    #: Engagement ids this principal may touch. Empty ⇒ all (admins/services).
    engagements: frozenset[str] = frozenset()

    def permissions(self) -> frozenset[Permission]:
        perms: set[Permission] = set()
        for role in self.roles:
            perms |= _ROLE_PERMISSIONS.get(role, frozenset())
        return frozenset(perms)

    def has(self, permission: Permission) -> bool:
        return permission in self.permissions()

    def may_access(self, engagement_id: str) -> bool:
        return not self.engagements or engagement_id in self.engagements


class AccessControl:
    """Authorises principals; raises :class:`AuthorizationError` on denial."""

    def check(
        self, principal: Principal, permission: Permission, *, engagement_id: str | None = None
    ) -> None:
        if not principal.has(permission):
            raise AuthorizationError(principal.id, permission.value, "missing permission")
        if engagement_id is not None and not principal.may_access(engagement_id):
            raise AuthorizationError(
                principal.id, permission.value, f"no access to engagement {engagement_id!r}"
            )

    def allows(
        self, principal: Principal, permission: Permission, *, engagement_id: str | None = None
    ) -> bool:
        try:
            self.check(principal, permission, engagement_id=engagement_id)
        except AuthorizationError:
            return False
        return True


# --- helpers ------------------------------------------------------------------


def operator(principal_id: str, *engagements: str) -> Principal:
    return Principal(id=principal_id, roles=frozenset({Role.OPERATOR}),
                     engagements=frozenset(engagements))


def approver(principal_id: str, *engagements: str) -> Principal:
    return Principal(id=principal_id, roles=frozenset({Role.APPROVER}),
                     engagements=frozenset(engagements))


def admin(principal_id: str) -> Principal:
    return Principal(id=principal_id, roles=frozenset({Role.ADMIN}))
