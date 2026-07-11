"""Converter — the remediator archetype (spec §4, step 6).

Turns each *confirmed* finding into a **proposed** control — a patch diff, a
config change, or a ticket. It proposes; it never applies. Applying a change is
a separate, human-gated action (:meth:`Converter.apply`, behind the
``apply_fix`` gate), so a real-world modification always passes a human.

The proposed content is generated deterministically from the finding; when a
model gateway is available it may add a human-readable rationale, but the
remediation's substance never depends on an LLM.
"""

from __future__ import annotations

from ...errors import GateDeniedError, StopConditionReached
from ...gateway.types import ChatMessage
from ...logging import get_logger
from ...schemas.findings import Finding, FindingState
from ...schemas.remediation import Remediation, RemediationKind, RemediationStatus
from ..base import Agent

_log = get_logger("agent.converter")


class Converter(Agent):
    """Proposes remediations for confirmed findings (propose-only)."""

    def _execute(self, targets: list[str]) -> None:
        for finding in self.ctx.store.findings(FindingState.CONFIRMED):
            if self.ctx.store.remediations(finding.id):
                continue  # already have a proposal for this finding
            remediation = self._propose(finding)
            self.ctx.store.add_remediation(remediation, emitted_by=self.spec.id)
            self.ctx.audit.append(
                engagement_id=self.ctx.engagement_id,
                actor=self.spec.id,
                action="remediation.propose",
                target=finding.asset,
                payload={
                    "finding_id": finding.id,
                    "remediation_id": remediation.id,
                    "kind": remediation.kind.value,
                },
            )
            self._note_finding()

    def _propose(self, finding: Finding) -> Remediation:
        if finding.type.startswith("CVE-"):
            kind, title, content = self._cve_patch(finding)
        elif finding.type.startswith("sqli"):
            kind, title, content = self._sqli_patch(finding)
        else:
            kind, title, content = self._generic_ticket(finding)
        rationale = self._rationale(finding, title)
        if rationale:
            content = f"{content}\n\n## Rationale\n{rationale}\n"
        return Remediation(
            engagement_id=self.ctx.engagement_id,
            finding_id=finding.id,
            kind=kind,
            title=title,
            content=content,
            proposed_by=self.spec.id,
        )

    @staticmethod
    def _cve_patch(f: Finding) -> tuple[RemediationKind, str, str]:
        product = (f.service or "component").split("/", 1)[0]
        cvss = f.metadata.get("cvss")
        title = f"Upgrade {product} to remediate {f.type}"
        content = (
            f"# Proposed remediation — {f.type}\n"
            f"- Asset: {f.asset}\n"
            f"- Component: {f.service}\n"
            f"- CVSS: {cvss}  ·  on KEV: {f.on_kev}  ·  exploit_prob: {f.exploit_prob}\n"
            f"- Priority: {f.priority.value if f.priority else 'n/a'}\n\n"
            f"## Action\n"
            f"Upgrade `{product}` beyond the affected version range and restart the "
            f"service. Validate configuration after upgrade.\n"
        )
        return RemediationKind.PATCH, title, content

    @staticmethod
    def _sqli_patch(f: Finding) -> tuple[RemediationKind, str, str]:
        md = f.metadata
        path, param = md.get("path", "?"), md.get("param", "?")
        title = f"Parameterise query for SQLi at {path} ({param})"
        content = (
            f"# Proposed remediation — boolean-blind SQLi\n"
            f"- Asset: {f.asset}\n- Endpoint: {path}  ·  Parameter: {param}\n\n"
            f"## Action\n"
            f"Replace string-built SQL with parameterised/prepared statements for "
            f"`{param}`. Add server-side input validation. As a compensating "
            f"control, deploy a WAF rule for `{path}` until the code fix ships.\n"
        )
        return RemediationKind.PATCH, title, content

    @staticmethod
    def _generic_ticket(f: Finding) -> tuple[RemediationKind, str, str]:
        title = f"Investigate and remediate: {f.type} on {f.asset}"
        content = (
            f"# Ticket — {f.type}\n- Asset: {f.asset}\n- Service: {f.service}\n"
            f"- Priority: {f.priority.value if f.priority else 'n/a'}\n\n"
            f"## Action\nTriage the finding, determine an appropriate control, and "
            f"track remediation to closure.\n"
        )
        return RemediationKind.TICKET, title, content

    def _rationale(self, finding: Finding, title: str) -> str | None:
        """Optional one-line human rationale via the BYOM gateway (audited)."""

        if self.ctx.gateway is None:
            return None
        prompt = (
            "In one sentence, explain to an engineer why this remediation matters. "
            f"Finding: {finding.type} on {finding.asset}. Proposed fix: {title}."
        )
        try:
            resp = self.ctx.gateway.complete(
                [ChatMessage.system("Be concise and factual."), ChatMessage.user(prompt)],
                tier=self.spec.model_tier,
                engagement_id=self.ctx.engagement_id,
                actor=self.spec.id,
            )
            return resp.text.strip()[:400]
        except Exception:
            return None

    # --- gated apply (never called during propose-only runs) ------------------

    def apply(self, remediation: Remediation, *, apply_audit_id: str | None = None) -> Remediation:
        """Mark a remediation applied — behind the ``apply_fix`` human gate.

        Applying a change has real-world effect, so it fails closed without an
        approving gate. Returns the updated remediation.
        """

        try:
            self.require_gate(
                "apply_fix",
                target=None,
                summary=f"apply remediation {remediation.id} for finding {remediation.finding_id}",
            )
        except (GateDeniedError, StopConditionReached):
            # Denied, or no gate wired: fail closed — the change is not applied.
            _log.warning("apply_fix not authorised; remediation left proposed",
                         remediation=remediation.id)
            return remediation

        entry = self.ctx.audit.append(
            engagement_id=self.ctx.engagement_id,
            actor=self.spec.id,
            action="fix.apply",
            payload={"remediation_id": remediation.id, "finding_id": remediation.finding_id},
        )
        updated = remediation.model_copy(
            update={
                "status": RemediationStatus.APPLIED,
                "applied_by": self.spec.id,
                "apply_audit_id": apply_audit_id or entry.entry_hash,
            }
        )
        self.ctx.store.update_remediation(updated)
        self._emit_fix_applied(updated)
        return updated

    def _emit_fix_applied(self, remediation: Remediation) -> None:
        from ...schemas.events import EventType

        self._emit(
            EventType.FIX_APPLIED,
            finding_id=remediation.finding_id,
            payload={"remediation_id": remediation.id},
        )
