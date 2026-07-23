"""Exploitability Matcher tests — interval match, KEV, reachability, scoring."""

from __future__ import annotations

import pytest

from attack_engine.correlate.feeds import LocalCveFeed
from attack_engine.correlate.matcher import ExploitabilityMatcher
from attack_engine.correlate.scoring import ExploitabilityScorer, ExploitFeatures
from attack_engine.governance.audit import AuditLog
from attack_engine.knowledge.store import KnowledgeStore
from attack_engine.schemas.findings import Asset, Finding, FindingState, Priority, Service


@pytest.fixture
def feed() -> LocalCveFeed:
    return LocalCveFeed.from_json()


@pytest.fixture
def store() -> KnowledgeStore:
    return KnowledgeStore("engagement-range")


@pytest.fixture
def audit() -> AuditLog:
    return AuditLog()


def _verified_service(store: KnowledgeStore, address: str, service: str, port: int,
                      reachable: bool) -> Finding:
    """Add an asset (reachable or internal-only) + a VERIFIED service finding."""

    store.add_asset(
        Asset(address=address, engagement_id="engagement-range",
              services=(Service(port=port),)),
        reachable_from_entry=reachable,
    )
    f = store.propose_finding(Finding(
        engagement_id="engagement-range", asset=address, service=service,
        type=f"exposed-service:{port}/tcp", metadata={"port": port}))
    return store.promote_finding(f.id, FindingState.VERIFIED, verified_by="version_regrab_oracle_v1")


class TestScorer:
    def test_kev_reachable_public_exploit_scores_high(self) -> None:
        s = ExploitabilityScorer()
        prob = s.score(ExploitFeatures(cvss=9.8, on_kev=True, reachable=True,
                                       has_public_exploit=True))
        assert prob > 0.85

    def test_internal_theoretical_scores_low(self) -> None:
        s = ExploitabilityScorer()
        prob = s.score(ExploitFeatures(cvss=5.1, on_kev=False, reachable=False,
                                       has_public_exploit=False))
        assert prob < 0.2

    def test_unreachable_is_always_informational(self) -> None:
        s = ExploitabilityScorer()
        # Even a scary CVSS+KEV, if unreachable, is deprioritised.
        assert s.priority(0.99, on_kev=True, reachable=False) is Priority.INFORMATIONAL

    def test_priority_bands(self) -> None:
        s = ExploitabilityScorer()
        assert s.priority(0.9, on_kev=True, reachable=True) is Priority.PATCH_IMMEDIATELY
        assert s.priority(0.72, on_kev=False, reachable=True) is Priority.HIGH
        assert s.priority(0.5, on_kev=False, reachable=True) is Priority.MEDIUM
        assert s.priority(0.1, on_kev=False, reachable=True) is Priority.LOW


class TestMatcher:
    def test_confirms_reachable_apache_as_patch_immediately(self, feed, store, audit) -> None:
        _verified_service(store, "10.5.0.10", "Apache httpd/2.4.49", 80, reachable=True)
        report = ExploitabilityMatcher(feed, store, audit).run()
        assert report.patch_immediately >= 1
        confirmed = store.findings(FindingState.CONFIRMED)
        apache_cves = [f for f in confirmed if f.type.startswith("CVE-2021-417")]
        assert apache_cves
        top = max(apache_cves, key=lambda f: f.exploit_prob or 0)
        assert top.on_kev is True
        assert top.priority is Priority.PATCH_IMMEDIATELY
        assert top.exploit_prob > 0.85

    def test_ignores_internal_only_theoretical_cve(self, feed, store, audit) -> None:
        # MySQL 5.5.61 on an INTERNAL-only host (not reachable from entry).
        _verified_service(store, "10.5.0.99", "MySQL/5.5.61", 3306, reachable=False)
        report = ExploitabilityMatcher(feed, store, audit).run()
        confirmed = store.findings(FindingState.CONFIRMED)
        mysql = [f for f in confirmed if f.type == "CVE-2012-2122"]
        assert mysql, "CVE should still be recorded"
        assert mysql[0].priority is Priority.INFORMATIONAL  # deprioritised
        assert report.patch_immediately == 0
        assert report.deprioritized >= 1

    def test_no_false_positive_on_patched_version(self, feed, store, audit) -> None:
        # Apache 2.4.50 is FIXED for CVE-2021-41773 (introduced 2.4.49, fixed 2.4.50).
        _verified_service(store, "10.5.0.10", "Apache httpd/2.4.50", 80, reachable=True)
        ExploitabilityMatcher(feed, store, audit).run()
        confirmed = store.findings(FindingState.CONFIRMED)
        assert not any(f.type == "CVE-2021-41773" for f in confirmed)  # the classic FP, avoided

    def test_correlation_is_audited(self, feed, store, audit) -> None:
        _verified_service(store, "10.5.0.10", "Apache httpd/2.4.49", 80, reachable=True)
        ExploitabilityMatcher(feed, store, audit).run()
        assert any(e.action == "finding.correlate" for e in audit.entries())
        assert audit.verify() is True

    def test_only_verified_services_correlated(self, feed, store, audit) -> None:
        # A merely PROPOSED (unverified) service must not be correlated.
        store.propose_finding(Finding(
            engagement_id="engagement-range", asset="10.5.0.10",
            service="Apache httpd/2.4.49", type="exposed-service:80/tcp"))
        report = ExploitabilityMatcher(feed, store, audit).run()
        assert report.services_scanned == 0


class TestImpactEnrichment:
    """#3 — a confirmed finding must carry impact (CVSS/severity), how-to-fix
    (remediation), and why-it-is-reachable so a defender can triage it."""

    def _verified_vuln(self, store: KnowledgeStore, address: str, ftype: str,
                       reachable: bool) -> Finding:
        store.add_asset(
            Asset(address=address, engagement_id="engagement-range"),
            reachable_from_entry=reachable,
        )
        f = store.propose_finding(Finding(
            engagement_id="engagement-range", asset=address, type=ftype,
            metadata={"param": "cmd"}))
        return store.promote_finding(f.id, FindingState.VERIFIED, verified_by="cmdi_exec_oracle_v1")

    def test_oracle_vuln_confirmed_with_cvss_severity_remediation(self, feed, store, audit) -> None:
        self._verified_vuln(store, "10.5.0.12", "command-injection", reachable=True)
        ExploitabilityMatcher(feed, store, audit).run()
        confirmed = store.findings(FindingState.CONFIRMED)
        cmdi = [f for f in confirmed if f.type == "command-injection"]
        assert cmdi, "oracle-proven cmdi must be confirmed"
        meta = cmdi[0].metadata
        assert meta["cvss"] == 9.8
        assert meta["severity"] == "patch_immediately"
        assert "shell" in meta["remediation"].lower()
        assert cmdi[0].priority is Priority.PATCH_IMMEDIATELY

    def test_proven_finding_reachability_reason_cites_the_probe(self, feed, store, audit) -> None:
        self._verified_vuln(store, "10.5.0.12", "sqli", reachable=True)
        ExploitabilityMatcher(feed, store, audit).run()
        sqli = [f for f in store.findings(FindingState.CONFIRMED) if f.type == "sqli"]
        assert sqli
        # verified_by is set → the reason must attest a live probe proved it.
        assert "oracle confirmed" in sqli[0].metadata["reachability_reason"].lower()

    def test_cve_finding_carries_remediation_and_reachability(self, feed, store, audit) -> None:
        _verified_service(store, "10.5.0.10", "Apache httpd/2.4.49", 80, reachable=True)
        ExploitabilityMatcher(feed, store, audit).run()
        cves = [f for f in store.findings(FindingState.CONFIRMED)
                if f.type.startswith("CVE-2021-417")]
        assert cves
        top = max(cves, key=lambda f: f.exploit_prob or 0)
        assert "upgrade" in top.metadata["remediation"].lower()
        assert top.metadata["reachability_reason"]
        assert "KEV" in top.metadata["remediation"]  # on-KEV note appended
