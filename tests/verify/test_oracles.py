"""Oracle tests — deterministic confirm/deny of proposed findings."""

from __future__ import annotations

import pytest

from attack_engine.schemas.findings import Finding
from attack_engine.verify.oracles.sqli_boolean_blind import SqliBooleanBlindOracle
from attack_engine.verify.oracles.version_regrab import VersionRegrabOracle

from .conftest import SqliRangeSandbox, make_verify_ctx


def sqli_finding() -> Finding:
    return Finding(
        engagement_id="engagement-range",
        asset="10.5.0.10",
        type="sqli-boolean-blind",
        title="candidate SQLi in q",
        metadata={"scheme": "http", "port": 3000, "path": "/rest/products/search",
                  "param": "q", "base_value": "apples"},
    )


class TestSqliBooleanBlindOracle:
    def test_confirms_vulnerable_endpoint(self, scope, audit) -> None:
        ctx = make_verify_ctx(scope, audit, SqliRangeSandbox(vulnerable=True))
        result = SqliBooleanBlindOracle().verify(sqli_finding(), ctx)
        assert result.passed is True
        assert result.confidence == 1.0
        assert result.measurements["true_signature"] != result.measurements["false_signature"]
        # Every probe was audited.
        assert len(result.evidence) == 12  # 6 trials × 2 probes

    def test_rejects_non_vulnerable_endpoint(self, scope, audit) -> None:
        ctx = make_verify_ctx(scope, audit, SqliRangeSandbox(vulnerable=False))
        result = SqliBooleanBlindOracle().verify(sqli_finding(), ctx)
        assert result.passed is False
        # No differential → true and false signatures identical.
        assert result.measurements["true_signature"] == result.measurements["false_signature"]

    def test_missing_param_fails_cleanly(self, scope, audit) -> None:
        ctx = make_verify_ctx(scope, audit, SqliRangeSandbox())
        f = Finding(engagement_id="engagement-range", asset="10.5.0.10",
                    type="sqli-boolean-blind")  # no metadata
        result = SqliBooleanBlindOracle().verify(f, ctx)
        assert result.passed is False
        assert "param" in result.detail

    def test_handles_only_sqli(self) -> None:
        o = SqliBooleanBlindOracle()
        assert o.handles(sqli_finding())
        assert not o.handles(
            Finding(engagement_id="e", asset="a", type="exposed-service:80/tcp")
        )

    def test_trials_below_min_rejected(self) -> None:
        with pytest.raises(ValueError, match="min_trials"):
            SqliBooleanBlindOracle(trials=2, min_trials=5)


class TestVersionRegrabOracle:
    def _svc_finding(self, service: str) -> Finding:
        return Finding(
            engagement_id="engagement-range",
            asset="10.5.0.10",
            type="exposed-service:80/tcp",
            service=service,
            metadata={"port": 80},
        )

    def test_confirms_matching_version(self, scope, audit) -> None:
        ctx = make_verify_ctx(scope, audit, SqliRangeSandbox())
        # nmap fixture reports Apache httpd 2.4.49 on :80.
        result = VersionRegrabOracle().verify(self._svc_finding("Apache httpd/2.4.49"), ctx)
        assert result.passed is True
        assert "confirms" in result.detail

    def test_rejects_contradicting_product(self, scope, audit) -> None:
        ctx = make_verify_ctx(scope, audit, SqliRangeSandbox())
        result = VersionRegrabOracle().verify(self._svc_finding("nginx/1.25.0"), ctx)
        assert result.passed is False
        assert "contradicts" in result.detail

    def test_rejects_when_port_closed_on_regrab(self, scope, audit) -> None:
        ctx = make_verify_ctx(scope, audit, SqliRangeSandbox())
        f = Finding(
            engagement_id="engagement-range", asset="10.5.0.10",
            type="exposed-service:9999/tcp", service="mystery/1.0",
            metadata={"port": 9999},
        )
        result = VersionRegrabOracle().verify(f, ctx)
        assert result.passed is False
        assert "not open" in result.detail

    def test_handles_only_exposed_service(self) -> None:
        o = VersionRegrabOracle()
        assert o.handles(self._svc_finding("Apache/2.4.49"))
        assert not o.handles(
            Finding(engagement_id="e", asset="a", type="sqli-boolean-blind")
        )
