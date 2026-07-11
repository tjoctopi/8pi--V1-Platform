"""Verifier tests — promotes proposed findings via oracles (accuracy gate)."""

from __future__ import annotations

from attack_engine.schemas.findings import Finding, FindingState
from attack_engine.verify.oracles import default_oracle_registry
from attack_engine.verify.verifier import Verifier

from .conftest import SqliRangeSandbox, make_verify_ctx


def _seed(ctx) -> None:
    # A real service observation (verifies), a vulnerable SQLi candidate
    # (verifies), and a web-path with no oracle (skipped).
    ctx.store.propose_finding(Finding(
        engagement_id="engagement-range", asset="10.5.0.10",
        type="exposed-service:80/tcp", service="Apache httpd/2.4.49",
        metadata={"port": 80}))
    ctx.store.propose_finding(Finding(
        engagement_id="engagement-range", asset="10.5.0.10",
        type="sqli-boolean-blind",
        metadata={"scheme": "http", "port": 3000, "path": "/rest/products/search",
                  "param": "q", "base_value": "apples"}))
    ctx.store.propose_finding(Finding(
        engagement_id="engagement-range", asset="10.5.0.10", type="web-path:admin"))


def test_verifier_promotes_and_skips(scope, audit) -> None:
    ctx = make_verify_ctx(scope, audit, SqliRangeSandbox(vulnerable=True))
    _seed(ctx)
    report = Verifier(default_oracle_registry(), ctx).run()

    # exposed-service (Apache) + sqli verify; web-path has no oracle (skipped).
    assert report.verified == 2
    assert report.skipped == 1  # web-path
    assert len(ctx.store.findings(FindingState.VERIFIED)) == 2
    # Nothing is CONFIRMED yet — that's the correlator's job (rule #1).
    assert ctx.store.findings(FindingState.CONFIRMED) == []


def test_every_verification_is_audited(scope, audit) -> None:
    ctx = make_verify_ctx(scope, audit, SqliRangeSandbox(vulnerable=True))
    ctx.store.propose_finding(Finding(
        engagement_id="engagement-range", asset="10.5.0.10",
        type="sqli-boolean-blind",
        metadata={"port": 3000, "path": "/x", "param": "q", "base_value": "a"}))
    Verifier(default_oracle_registry(), ctx).run()
    verify_entries = [e for e in audit.entries() if e.action == "finding.verify"]
    assert verify_entries
    assert verify_entries[0].payload["passed"] is True
    assert audit.verify() is True


def test_non_vulnerable_sqli_is_rejected(scope, audit) -> None:
    ctx = make_verify_ctx(scope, audit, SqliRangeSandbox(vulnerable=False))
    f = ctx.store.propose_finding(Finding(
        engagement_id="engagement-range", asset="10.5.0.10",
        type="sqli-boolean-blind",
        metadata={"port": 3000, "path": "/x", "param": "q", "base_value": "a"}))
    Verifier(default_oracle_registry(), ctx).run()
    updated = ctx.store.get_finding(f.id)
    assert updated.state is FindingState.REJECTED
    assert "sqli_boolean_blind_oracle_v1" in updated.rejected_reason
