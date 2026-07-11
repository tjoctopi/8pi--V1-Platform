"""Metric-function tests: classification + calibration."""

from __future__ import annotations

import pytest

from attack_engine.evals.metrics import calibration_metrics, classification_metrics


class TestClassification:
    def test_perfect(self) -> None:
        pos = {("a", "x"), ("b", "y")}
        neg = {("c", "z")}
        m = classification_metrics(predicted=pos, positives=pos, negatives=neg)
        assert m.precision == 1.0 and m.recall == 1.0 and m.f1 == 1.0
        assert (m.tp, m.fp, m.fn, m.tn) == (2, 0, 0, 1)

    def test_false_positive_lowers_precision(self) -> None:
        pos = {("a", "x")}
        neg = {("c", "z")}
        m = classification_metrics(predicted={("a", "x"), ("c", "z")}, positives=pos, negatives=neg)
        assert m.tp == 1 and m.fp == 1
        assert m.precision == 0.5
        assert m.recall == 1.0

    def test_missed_positive_lowers_recall(self) -> None:
        pos = {("a", "x"), ("b", "y")}
        m = classification_metrics(predicted={("a", "x")}, positives=pos, negatives=set())
        assert m.recall == 0.5
        assert m.fn == 1

    def test_unlabelled_prediction_counts_as_fp(self) -> None:
        m = classification_metrics(
            predicted={("z", "unknown")}, positives={("a", "x")}, negatives=set()
        )
        assert m.fp == 1


class TestCalibration:
    def test_brier_perfect(self) -> None:
        pairs = [(1.0, 1), (0.0, 0), (1.0, 1)]
        m = calibration_metrics(pairs)
        assert m.brier == pytest.approx(0.0)
        assert m.ece == pytest.approx(0.0)

    def test_brier_worst(self) -> None:
        pairs = [(1.0, 0), (0.0, 1)]
        m = calibration_metrics(pairs)
        assert m.brier == pytest.approx(1.0)

    def test_ece_detects_miscalibration(self) -> None:
        # Model says 0.9 but is only right half the time → ECE ≈ 0.4.
        pairs = [(0.9, 1), (0.9, 0)]
        m = calibration_metrics(pairs, n_bins=10)
        assert m.ece == pytest.approx(0.4, abs=1e-9)

    def test_empty_pairs(self) -> None:
        m = calibration_metrics([])
        assert m.n == 0 and m.brier == 0.0

    def test_reliability_bins_populated(self) -> None:
        pairs = [(0.1, 0), (0.15, 0), (0.95, 1), (0.9, 1)]
        m = calibration_metrics(pairs, n_bins=10)
        assert m.n == 4
        assert sum(b.count for b in m.bins) == 4
