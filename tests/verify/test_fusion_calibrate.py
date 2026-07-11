"""Evidence fusion + calibration tests."""

from __future__ import annotations

import pytest

from attack_engine.verify.calibrate import IsotonicCalibrator, PlattCalibrator
from attack_engine.verify.fusion import Evidence, agreement_boost, fuse


class TestFusion:
    def test_agreement_raises_confidence(self) -> None:
        # Two independent sources at 0.8 should exceed either alone.
        fused = agreement_boost([0.8, 0.8])
        assert fused > 0.8

    def test_disagreement_lowers_confidence(self) -> None:
        # A confident "yes" and a confident "no" partially cancel toward prior.
        fused = agreement_boost([0.9, 0.1])
        assert 0.4 < fused < 0.6

    def test_single_evidence_at_prior_is_neutral(self) -> None:
        assert fuse([Evidence(0.5)], prior=0.5) == pytest.approx(0.5, abs=1e-6)

    def test_order_independence(self) -> None:
        a = fuse([Evidence(0.7), Evidence(0.9), Evidence(0.6)])
        b = fuse([Evidence(0.6), Evidence(0.7), Evidence(0.9)])
        assert a == pytest.approx(b, abs=1e-9)

    def test_weight_scales_influence(self) -> None:
        strong = fuse([Evidence(0.9, weight=2.0)])
        weak = fuse([Evidence(0.9, weight=0.5)])
        assert strong > weak > 0.5

    def test_more_agreeing_evidence_converges_up(self) -> None:
        assert agreement_boost([0.7] * 5) > agreement_boost([0.7] * 2)


def _synthetic_data() -> tuple[list[float], list[int]]:
    # Raw scores 0..1; label 1 becomes more likely as score rises, with noise.
    scores = [i / 20 for i in range(21)]
    labels = [0 if i < 10 else 1 for i in range(21)]
    labels[9], labels[11] = 1, 0  # a little noise near the boundary
    return scores, labels


class TestPlatt:
    def test_monotonic_and_bounded(self) -> None:
        scores, labels = _synthetic_data()
        cal = PlattCalibrator().fit(scores, labels)
        preds = cal.predict([0.0, 0.25, 0.5, 0.75, 1.0])
        assert all(0.0 <= p <= 1.0 for p in preds)
        assert preds == sorted(preds)  # non-decreasing
        assert preds[0] < 0.5 < preds[-1]

    def test_empty_fit_raises(self) -> None:
        with pytest.raises(ValueError):
            PlattCalibrator().fit([], [])

    def test_length_mismatch_raises(self) -> None:
        with pytest.raises(ValueError):
            PlattCalibrator().fit([0.1, 0.2], [1])


class TestIsotonic:
    def test_monotonic_nondecreasing(self) -> None:
        scores, labels = _synthetic_data()
        cal = IsotonicCalibrator().fit(scores, labels)
        preds = cal.predict([0.0, 0.2, 0.4, 0.6, 0.8, 1.0])
        assert all(0.0 <= p <= 1.0 for p in preds)
        assert preds == sorted(preds)

    def test_perfectly_separable_data(self) -> None:
        scores = [0.1, 0.2, 0.3, 0.7, 0.8, 0.9]
        labels = [0, 0, 0, 1, 1, 1]
        cal = IsotonicCalibrator().fit(scores, labels)
        assert cal.predict_one(0.1) < 0.5
        assert cal.predict_one(0.9) > 0.5

    def test_predict_before_fit_raises(self) -> None:
        with pytest.raises(RuntimeError):
            IsotonicCalibrator().predict_one(0.5)
