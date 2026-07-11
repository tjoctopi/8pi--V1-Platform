"""Attack-plan DAG + report tests."""

from __future__ import annotations

from attack_engine.knowledge.graph import AttackGraph
from attack_engine.orchestrator.plan import build_plan, prioritize_targets
from attack_engine.orchestrator.report import build_report
from attack_engine.schemas.findings import Asset, Finding, FindingState, Priority, Service


class TestPlan:
    def test_phases_are_topologically_ordered(self) -> None:
        plan = build_plan("assess", ["10.5.0.10"], AttackGraph())
        names = plan.phase_names()
        # Dependencies must be respected in the linearisation.
        assert names.index("recon") < names.index("verify_services")
        assert names.index("web") < names.index("exploit_confirm")
        assert names.index("exploit_confirm") < names.index("verify_vulns")
        assert names.index("correlate") < names.index("convert")
        assert names[-1] == "report"

    def test_reachable_targets_prioritised_first(self) -> None:
        g = AttackGraph()
        g.add_asset(Asset(address="10.5.0.10", engagement_id="e",
                          services=(Service(port=80),)))
        g.add_asset(Asset(address="10.5.0.99", engagement_id="e",
                          services=(Service(port=3306),)), reachable_from_entry=False)
        ordered = prioritize_targets(["10.5.0.99", "10.5.0.10"], g)
        assert ordered[0] == "10.5.0.10"  # reachable first

    def test_unknown_targets_sort_last_stably(self) -> None:
        g = AttackGraph()
        g.add_asset(Asset(address="10.5.0.10", engagement_id="e"))
        ordered = prioritize_targets(["10.5.0.10", "10.5.0.200"], g)
        assert ordered == ["10.5.0.10", "10.5.0.200"]


class TestReport:
    def _confirmed(self, priority: Priority, prob: float, ftype: str) -> Finding:
        f = Finding(engagement_id="e", asset="10.5.0.10", type=ftype,
                    verified_by="oracle", priority=priority, exploit_prob=prob)
        return f.model_copy(update={"state": FindingState.CONFIRMED})

    def test_confirmed_sorted_by_priority_then_prob(self) -> None:
        findings = [
            self._confirmed(Priority.HIGH, 0.7, "CVE-A"),
            self._confirmed(Priority.PATCH_IMMEDIATELY, 0.95, "CVE-B"),
            self._confirmed(Priority.PATCH_IMMEDIATELY, 0.85, "CVE-C"),
        ]
        report = build_report(
            engagement_id="e", goal="assess", findings=findings, remediations=[],
            asset_count=1, audit_entries=10, audit_intact=True, audit_head="abc123",
        )
        order = [f.type for f in report.confirmed]
        assert order == ["CVE-B", "CVE-C", "CVE-A"]  # patch_now (by prob) then high

    def test_risk_map_zeroes_unreachable_and_orders_by_risk(self) -> None:
        reachable = self._confirmed(Priority.HIGH, 0.8, "sqli-boolean-blind").model_copy(
            update={"reachable": True}
        )
        internal = self._confirmed(Priority.INFORMATIONAL, 0.9, "CVE-INTERNAL").model_copy(
            update={"reachable": False}
        )
        report = build_report(
            engagement_id="e", goal="assess", findings=[internal, reachable],
            remediations=[], asset_count=2, audit_entries=5, audit_intact=True, audit_head="h",
        )
        # The reachable finding tops the map even though the internal one has a
        # higher raw exploit_prob — reachability gates the risk to 0.
        assert report.risk_map[0].type == "sqli-boolean-blind"
        assert report.risk_map[0].risk == 0.8
        internal_entry = next(e for e in report.risk_map if e.type == "CVE-INTERNAL")
        assert internal_entry.risk == 0.0 and internal_entry.reachable is False

    def test_hardening_actions_from_remediations(self) -> None:
        from attack_engine.schemas.remediation import Remediation, RemediationKind

        rem = Remediation(engagement_id="e", finding_id="f-1", kind=RemediationKind.PATCH,
                          title="Upgrade Apache beyond 2.4.49", content="...")
        report = build_report(
            engagement_id="e", goal="assess", findings=[], remediations=[rem],
            asset_count=1, audit_entries=1, audit_intact=True, audit_head="h",
        )
        assert "Upgrade Apache beyond 2.4.49" in report.hardening_actions

    def test_markdown_renders_key_sections(self) -> None:
        report = build_report(
            engagement_id="engagement-range", goal="assess",
            findings=[self._confirmed(Priority.PATCH_IMMEDIATELY, 0.95, "CVE-2021-41773")],
            remediations=[], asset_count=2, audit_entries=20,
            audit_intact=True, audit_head="deadbeefcafe0000",
        )
        md = report.to_markdown()
        assert "# Engagement Report — engagement-range" in md
        assert "Risk map (reachability-prioritised)" in md
        assert "Hardening actions" in md
        assert "CVE-2021-41773" in md
        assert "intact" in md
