"""Close-the-loop re-test (spec §3 step 7).

After a fix is applied, the loop re-runs the *exact* detection that confirmed a
finding and checks whether it still fires. A CVE finding is re-tested by
re-grabbing the service version and re-checking the affected interval; a SQLi
finding by re-running its boolean-blind oracle. If the check no longer fires the
fix holds; if it still fires the finding is escalated with failed-retest
evidence. All probes go through the scope-enforced Tool Runner and are audited.
"""

from __future__ import annotations

from ..correlate.feeds import CveFeed
from ..correlate.matcher import _parse_service
from ..logging import get_logger
from ..schemas.findings import Finding
from ..schemas.remediation import RetestResult
from ..schemas.tools import ToolProfile
from ..verify.context import VerifyContext
from ..verify.oracles.sqli_boolean_blind import SqliBooleanBlindOracle

_log = get_logger("orchestrator.retest")


class RetestRunner:
    """Re-runs the exact confirming check for a finding against current state."""

    def __init__(self, ctx: VerifyContext, feed: CveFeed) -> None:
        self._ctx = ctx
        self._feed = feed
        self._sqli = SqliBooleanBlindOracle()

    def retest(self, finding: Finding) -> RetestResult:
        if finding.type.startswith("CVE-"):
            return self._retest_cve(finding)
        if finding.type.startswith("sqli"):
            return self._retest_sqli(finding)
        # No re-test path for this class → conservatively report unresolved.
        return RetestResult(
            finding_id=finding.id,
            fixed=False,
            detail=f"no re-test procedure for finding type {finding.type!r}",
        )

    def _retest_cve(self, finding: Finding) -> RetestResult:
        port = finding.metadata.get("port")
        product, _old_version = _parse_service(finding.service or "")
        profile = ToolProfile(
            preset="default", args={"ports": str(port)} if port else {}
        )
        result = self._ctx.tool_runner.run("nmap", finding.asset, profile)
        regrabbed = next(
            (p for p in result.parsed.get("ports", [])
             if port is None or int(p["port"]) == int(port)),
            None,
        )
        current_version = regrabbed.get("version") if regrabbed else None
        # Still vulnerable iff this exact CVE still matches the current version.
        still = any(
            c.id == finding.type for c in self._feed.match(product, current_version)
        )
        return RetestResult(
            finding_id=finding.id,
            fixed=not still,
            detail=(
                f"re-grab observed version {current_version!r}; "
                f"{finding.type} {'still matches' if still else 'no longer matches'}"
            ),
            evidence=(f"raw:{result.audit_id}",),
        )

    def _retest_sqli(self, finding: Finding) -> RetestResult:
        verdict = self._sqli.verify(finding, self._ctx)
        return RetestResult(
            finding_id=finding.id,
            fixed=not verdict.passed,
            detail=(
                "boolean-blind differential "
                f"{'still present' if verdict.passed else 'no longer present'}"
            ),
            evidence=verdict.evidence,
        )
