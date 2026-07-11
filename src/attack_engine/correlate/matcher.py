"""Exploitability Matcher — the correlator (spec §3 step 4, diagram agent #4).

Takes VERIFIED service findings, maps each to CVEs via correct interval version
matching, checks CISA KEV, derives reachability from the attack graph, and
assigns a calibrated exploitability probability + priority. It then confirms a
CVE finding only when the version genuinely falls in the affected interval —
"internet-facing + on KEV + reachable" becomes *patch now*, while an
internal-only theoretical CVE is deprioritised automatically.

The version interval match is itself a deterministic verification, so the
matcher promotes PROPOSED → VERIFIED → CONFIRMED for a matched CVE (rule #1);
the confirmation authority recorded is ``cve_interval_match_v1``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..governance.audit import AuditLog
from ..knowledge.store import KnowledgeStore
from ..logging import get_logger
from ..schemas.findings import VULN_TYPE_PREFIXES, Finding, FindingState
from .feeds import CveFeed, CveRecord
from .scoring import ExploitabilityScorer, ExploitFeatures

_log = get_logger("correlate.matcher")

INTERVAL_ORACLE_ID = "cve_interval_match_v1"


@dataclass
class MatchReport:
    services_scanned: int = 0
    cves_confirmed: int = 0
    patch_immediately: int = 0
    deprioritized: int = 0
    confirmed_ids: list[str] = field(default_factory=list)


class ExploitabilityMatcher:
    """Correlates verified services to scored, prioritised CVE findings."""

    def __init__(
        self,
        feed: CveFeed,
        store: KnowledgeStore,
        audit: AuditLog,
        *,
        scorer: ExploitabilityScorer | None = None,
    ) -> None:
        self._feed = feed
        self._store = store
        self._audit = audit
        self._scorer = scorer or ExploitabilityScorer()

    def run(self) -> MatchReport:
        report = MatchReport()
        for finding in self._store.findings(FindingState.VERIFIED):
            if finding.type.startswith("exposed-service:") and finding.service:
                report.services_scanned += 1
                product, version = _parse_service(finding.service)
                for cve in self._feed.match(product, version):
                    self._confirm_cve(finding, cve, report)
            elif finding.type.startswith(VULN_TYPE_PREFIXES):
                # An oracle-verified vulnerability (e.g. SQLi) has no CVE to match;
                # finalise it directly into CONFIRMED with a reachability-based
                # priority so it flows to remediation.
                self._finalize_vuln(finding, report)
        return report

    def _finalize_vuln(self, finding: Finding, report: MatchReport) -> None:
        asset = self._store.get_asset(finding.asset)
        reachable = (
            self._store.graph.is_reachable(asset.id)
            if asset is not None
            else finding.reachable
        )
        prob = finding.exploit_prob if finding.exploit_prob is not None else 0.6
        priority = self._scorer.priority(prob, on_kev=False, reachable=reachable)
        confirmed = self._store.promote_finding(
            finding.id,
            FindingState.CONFIRMED,
            priority=priority,
            emitted_by="exploitability_matcher",
        )
        self._audit.append(
            engagement_id=finding.engagement_id,
            actor="exploitability_matcher",
            action="finding.correlate",
            target=finding.asset,
            payload={
                "type": finding.type,
                "reachable": reachable,
                "exploit_prob": prob,
                "priority": priority.value,
                "finding_id": confirmed.id,
            },
        )
        report.cves_confirmed += 1
        report.confirmed_ids.append(confirmed.id)
        if priority.value == "patch_immediately":
            report.patch_immediately += 1
        elif priority.value in ("low", "informational"):
            report.deprioritized += 1

    def _confirm_cve(
        self, service_finding: Finding, cve: CveRecord, report: MatchReport
    ) -> None:
        asset = self._store.get_asset(service_finding.asset)
        reachable = (
            self._store.graph.is_reachable(asset.id)
            if asset is not None
            else service_finding.reachable
        )
        features = ExploitFeatures(
            cvss=cve.cvss,
            on_kev=cve.kev,
            reachable=reachable,
            has_public_exploit=cve.has_public_exploit,
        )
        prob = self._scorer.score(features)
        priority = self._scorer.priority(prob, on_kev=cve.kev, reachable=reachable)

        cve_finding = Finding(
            engagement_id=service_finding.engagement_id,
            asset=service_finding.asset,
            service=service_finding.service,
            type=cve.id,
            title=f"{cve.id}: {cve.description}",
            on_kev=cve.kev,
            exploit_prob=round(prob, 4),
            priority=priority,
            evidence=service_finding.evidence,
            proposed_by="exploitability_matcher",
            metadata={
                "cvss": cve.cvss,
                "cwe": cve.cwe,
                "from_service": service_finding.id,
                "port": service_finding.metadata.get("port"),
            },
        )
        proposed = self._store.propose_finding(cve_finding, emitted_by="exploitability_matcher")
        # A duplicate (already confirmed this CVE on this asset) returns the rep.
        if proposed.state is FindingState.CONFIRMED:
            return

        # The interval match IS the deterministic verification (rule #1).
        self._store.promote_finding(
            proposed.id,
            FindingState.VERIFIED,
            verified_by=INTERVAL_ORACLE_ID,
            emitted_by="exploitability_matcher",
        )
        confirmed = self._store.promote_finding(
            proposed.id, FindingState.CONFIRMED, emitted_by="exploitability_matcher"
        )

        self._audit.append(
            engagement_id=service_finding.engagement_id,
            actor="exploitability_matcher",
            action="finding.correlate",
            target=service_finding.asset,
            payload={
                "cve": cve.id,
                "on_kev": cve.kev,
                "reachable": reachable,
                "cvss": cve.cvss,
                "exploit_prob": round(prob, 4),
                "priority": priority.value,
                "finding_id": confirmed.id,
            },
        )
        report.cves_confirmed += 1
        report.confirmed_ids.append(confirmed.id)
        if priority.value == "patch_immediately":
            report.patch_immediately += 1
        elif priority.value in ("low", "informational"):
            report.deprioritized += 1
        _log.info(
            "cve confirmed",
            cve=cve.id,
            asset=service_finding.asset,
            reachable=reachable,
            prob=round(prob, 3),
            priority=priority.value,
        )


def _parse_service(service: str) -> tuple[str, str | None]:
    """Split a cpe-ish hint like ``Apache httpd/2.4.49`` into (product, version)."""

    if "/" in service:
        left, right = service.rsplit("/", 1)
        right = right.strip()
        if right and right[0].isdigit():
            return left.strip(), right
    return service.strip(), None
