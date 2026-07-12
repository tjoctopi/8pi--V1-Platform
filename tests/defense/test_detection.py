"""Evasion & detection testing (O6) — purple-team detection-coverage report."""

from __future__ import annotations

from attack_engine.defense.detection import DetectionTester, default_detection_ruleset
from attack_engine.governance.audit import AuditLog


def _audit_with_offense() -> AuditLog:
    audit = AuditLog()
    eng = "engagement-det"
    # Telemetry of an emulation run: recon + exploit + kerberoast (but NO AD enum).
    audit.append(engagement_id=eng, actor="a", action="tool.run", target="h",
                 payload={"tool": "nmap"})
    audit.append(engagement_id=eng, actor="a", action="tool.run", target="h",
                 payload={"tool": "kerberoast"})
    audit.append(engagement_id=eng, actor="a", action="exploit.confirm", target="h",
                 payload={"module": "x"})
    return audit


def test_ruleset_has_attack_mapped_rules() -> None:
    rules = default_detection_ruleset()
    techniques = {r.technique for r in rules}
    assert {"T1595", "T1190", "T1558.003", "T1087"} <= techniques


def test_evaluate_reports_fired_detections() -> None:
    report = DetectionTester().evaluate(_audit_with_offense().entries())
    detected = set(report.detected)
    assert "T1595" in detected      # nmap scanning
    assert "T1190" in detected      # exploit.confirm
    assert "T1558.003" in detected  # kerberoast
    assert "T1087" not in detected  # no bloodhound ran → nothing to detect


def test_evaluate_for_reports_evasions() -> None:
    # We exercised T1595, T1190, T1558.003, AND T1087 — but T1087 left no telemetry
    # a rule caught (we claim we ran AD enum but bloodhound isn't in the trail),
    # so it is reported as an EVASION.
    exercised = {"T1595", "T1190", "T1558.003", "T1087"}
    report = DetectionTester().evaluate_for(_audit_with_offense().entries(), exercised)
    assert set(report.detected) == {"T1595", "T1190", "T1558.003"}
    assert report.evaded == ["T1087"]
    assert report.coverage == 0.75  # 3 of 4 detected
    md = report.to_markdown()
    assert "Detection coverage" in md and "EVADED" in md
