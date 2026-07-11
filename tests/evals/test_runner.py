"""Eval runner tests — score confirmed findings vs the range ground truth."""

from __future__ import annotations

from pathlib import Path

import pytest

from attack_engine.evals.dataset import GroundTruth
from attack_engine.evals.runner import EvalRunner
from attack_engine.evals.tracking import LocalJsonTracker
from attack_engine.schemas.findings import Finding, FindingState, Priority

LABELS = Path(__file__).resolve().parents[2] / "src/attack_engine/evals/data/range_labels.json"


def _confirmed(asset: str, type_: str, prob: float, priority: Priority) -> Finding:
    f = Finding(engagement_id="e", asset=asset, type=type_, verified_by="oracle",
                exploit_prob=prob, priority=priority)
    return f.model_copy(update={"state": FindingState.CONFIRMED})


@pytest.fixture
def ground_truth() -> GroundTruth:
    return GroundTruth.from_json(LABELS)


def test_ground_truth_loads(ground_truth: GroundTruth) -> None:
    assert ("10.5.0.10", "CVE-2021-41773") in ground_truth.positives()
    assert ("10.5.0.99", "CVE-2012-2122") in ground_truth.negatives()


def test_perfect_engine_scores_100(ground_truth: GroundTruth) -> None:
    # Engine confirms exactly the two planted vulns, high prob; ignores the trap.
    findings = [
        _confirmed("10.5.0.10", "CVE-2021-41773", 0.95, Priority.PATCH_IMMEDIATELY),
        _confirmed("10.5.0.10", "sqli-boolean-blind", 0.9, Priority.HIGH),
    ]
    report = EvalRunner(ground_truth).evaluate(findings, model_id="baseline")
    assert report.precision == 1.0
    assert report.recall == 1.0
    assert report.fp == 0

    # Calibration: the trap (label 0) got prob 0.0 (not flagged), positives ~0.9.
    assert report.brier < 0.05


def test_false_positive_on_trap_hurts_precision(ground_truth: GroundTruth) -> None:
    findings = [
        _confirmed("10.5.0.10", "CVE-2021-41773", 0.95, Priority.PATCH_IMMEDIATELY),
        _confirmed("10.5.0.10", "sqli-boolean-blind", 0.9, Priority.HIGH),
        # Wrongly confirmed the internal-only theoretical CVE as actionable:
        _confirmed("10.5.0.99", "CVE-2012-2122", 0.8, Priority.HIGH),
    ]
    report = EvalRunner(ground_truth).evaluate(findings)
    assert report.fp == 1
    assert report.precision < 1.0


def test_missed_vuln_hurts_recall(ground_truth: GroundTruth) -> None:
    findings = [_confirmed("10.5.0.10", "CVE-2021-41773", 0.95, Priority.PATCH_IMMEDIATELY)]
    report = EvalRunner(ground_truth).evaluate(findings)
    assert report.recall == pytest.approx(0.5)  # caught 1 of 2 planted vulns
    assert report.fn == 1


def test_tracker_records_run(ground_truth: GroundTruth, tmp_path: Path) -> None:
    tracker = LocalJsonTracker(tmp_path / "runs.jsonl")
    findings = [_confirmed("10.5.0.10", "CVE-2021-41773", 0.95, Priority.PATCH_IMMEDIATELY)]
    EvalRunner(ground_truth, tracker=tracker).evaluate(findings, name="run-1", model_id="m1")
    runs = tracker.runs()
    assert len(runs) == 1
    assert runs[0]["name"] == "run-1"
    assert runs[0]["params"]["model_id"] == "m1"
    assert "precision" in runs[0]["metrics"]


def test_report_markdown(ground_truth: GroundTruth) -> None:
    findings = [_confirmed("10.5.0.10", "CVE-2021-41773", 0.95, Priority.PATCH_IMMEDIATELY)]
    md = EvalRunner(ground_truth).evaluate(findings, model_id="llama").to_markdown()
    assert "Eval — range-eval" in md
    assert "Precision" in md and "Calibration" in md
