"""The Verifier — the accuracy gate (spec §3 step 3, diagram agent #3).

Consumes PROPOSED findings from the blackboard, routes each to the deterministic
oracle that handles it, and promotes it to VERIFIED (oracle passed) or REJECTED
(oracle failed). Findings with no registered oracle are left PROPOSED — the
Verifier never guesses. Every verdict is audited with the oracle id, so the
record shows exactly what promoted (or killed) each finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..logging import get_logger
from ..schemas.findings import VULN_TYPE_PREFIXES, Finding, FindingState
from .calibrate import Calibrator
from .context import VerifyContext
from .oracles.base import OracleRegistry

_log = get_logger("verify.verifier")

_VULN_PREFIXES = VULN_TYPE_PREFIXES


@dataclass
class VerifyReport:
    verified: int = 0
    rejected: int = 0
    skipped: int = 0  # no oracle handles this finding class
    verified_ids: list[str] = field(default_factory=list)
    rejected_ids: list[str] = field(default_factory=list)


class Verifier:
    """Runs oracles over proposed findings and promotes them (rule #1)."""

    def __init__(
        self,
        registry: OracleRegistry,
        ctx: VerifyContext,
        *,
        calibrator: Calibrator | None = None,
    ) -> None:
        self._registry = registry
        self._ctx = ctx
        self._calibrator = calibrator

    def _score_for(self, finding: Finding, confidence: float) -> float | None:
        """Calibrated exploitability for a vulnerability finding, else None."""

        if not any(finding.type.startswith(p) for p in _VULN_PREFIXES):
            return None
        if self._calibrator is not None and getattr(self._calibrator, "fitted", False):
            return round(self._calibrator.predict_one(confidence), 4)
        return round(confidence, 4)

    def run(self) -> VerifyReport:
        report = VerifyReport()
        for finding in self._ctx.store.findings(FindingState.PROPOSED):
            self._verify_one(finding, report)
        return report

    def _verify_one(self, finding: Finding, report: VerifyReport) -> None:
        oracle = self._registry.for_finding(finding)
        if oracle is None:
            report.skipped += 1
            return

        result = oracle.verify(finding, self._ctx)
        self._ctx.audit.append(
            engagement_id=self._ctx.engagement_id,
            actor=oracle.oracle_id,
            action="finding.verify",
            target=finding.asset,
            payload={
                "finding_id": finding.id,
                "type": finding.type,
                "passed": result.passed,
                "detail": result.detail,
                "confidence": result.confidence,
                "measurements": result.measurements,
            },
        )

        if result.passed:
            self._ctx.store.promote_finding(
                finding.id,
                FindingState.VERIFIED,
                verified_by=result.oracle_id,
                evidence=result.evidence,
                exploit_prob=self._score_for(finding, result.confidence),
                emitted_by="verifier",
            )
            report.verified += 1
            report.verified_ids.append(finding.id)
            _log.info("finding verified", finding=finding.id, oracle=oracle.oracle_id)
        else:
            self._ctx.store.promote_finding(
                finding.id,
                FindingState.REJECTED,
                rejected_reason=f"{oracle.oracle_id}: {result.detail}",
                evidence=result.evidence,
                emitted_by="verifier",
            )
            report.rejected += 1
            report.rejected_ids.append(finding.id)
            _log.info("finding rejected", finding=finding.id, oracle=oracle.oracle_id)
