"""Calibration fitting + wiring (B4).

Proves fitting actually improves ECE/Brier on miscalibrated data, and that the
fitted calibrator is threaded into both the scorer and the Verifier — so a
promoted finding's exploit_prob is calibrated, not a raw sigmoid.
"""

from __future__ import annotations

import json

import pytest

from attack_engine.config import Settings
from attack_engine.correlate.scoring import ExploitabilityScorer, ExploitFeatures
from attack_engine.engine import build_calibrator
from attack_engine.governance.audit import AuditLog
from attack_engine.schemas import Scope
from attack_engine.schemas.findings import Finding, FindingState
from attack_engine.verify.calibration import (
    calibration_report,
    fit_calibrator,
    load_calibration_samples,
)
from attack_engine.verify.oracles import default_oracle_registry
from attack_engine.verify.verifier import Verifier
from tests.verify.conftest import make_verify_ctx
from tests.verify.test_impact_oracles import _LfiSandbox

# Systematically over-confident data: raw score >> the true positive rate in each
# group, so calibration has real work to do.
_MISCALIBRATED: list[tuple[float, int]] = (
    [(0.8, 1)] * 4 + [(0.8, 0)] * 6        # score 0.8, only 40% positive
    + [(0.3, 1)] * 2 + [(0.3, 0)] * 8      # score 0.3, only 20% positive
    + [(0.95, 1)] * 9 + [(0.95, 0)] * 1    # score 0.95, 90% positive
)


# --- fitting improves calibration -----------------------------------------------


def test_isotonic_fit_lowers_ece_and_brier() -> None:
    cal = fit_calibrator(_MISCALIBRATED, "isotonic")
    report = calibration_report(cal, _MISCALIBRATED)
    assert report["improved"] is True
    assert report["after"]["ece"] < report["before"]["ece"]
    assert report["after"]["brier"] <= report["before"]["brier"]


def test_platt_fit_produces_valid_probabilities() -> None:
    cal = fit_calibrator(_MISCALIBRATED, "platt")
    assert cal.fitted
    for score in (0.0, 0.3, 0.8, 0.95, 1.0):
        assert 0.0 <= cal.predict_one(score) <= 1.0
    assert calibration_report(cal, _MISCALIBRATED)["improved"] is True


def test_isotonic_maps_overconfident_score_down() -> None:
    cal = fit_calibrator(_MISCALIBRATED, "isotonic")
    # 0.8 raw with a true 40% rate should calibrate well below 0.8.
    assert cal.predict_one(0.8) < 0.6


# --- samples file ---------------------------------------------------------------


def test_load_calibration_samples(tmp_path) -> None:
    path = tmp_path / "cal.json"
    path.write_text(json.dumps({"samples": [{"score": 0.9, "label": 1},
                                            {"score": 0.2, "label": 0}]}))
    assert load_calibration_samples(path) == [(0.9, 1), (0.2, 0)]


def test_load_calibration_rejects_empty(tmp_path) -> None:
    path = tmp_path / "cal.json"
    path.write_text(json.dumps({"samples": []}))
    with pytest.raises(ValueError, match="no calibration samples"):
        load_calibration_samples(path)


def test_load_calibration_rejects_bad_label(tmp_path) -> None:
    path = tmp_path / "cal.json"
    path.write_text(json.dumps({"samples": [{"score": 0.5, "label": 2}]}))
    with pytest.raises(ValueError, match="label must be 0 or 1"):
        load_calibration_samples(path)


# --- engine build_calibrator ----------------------------------------------------


def test_build_calibrator_from_config(tmp_path) -> None:
    path = tmp_path / "cal.json"
    path.write_text(json.dumps({"samples": [{"score": s, "label": y}
                                            for s, y in _MISCALIBRATED]}))
    settings = Settings(calibration_path=str(path), calibration_method="isotonic",
                        _env_file=None)
    cal = build_calibrator(settings)
    assert cal is not None and cal.fitted


def test_build_calibrator_none_without_config() -> None:
    assert build_calibrator(Settings(_env_file=None)) is None


# --- wiring: scorer + Verifier use the fitted calibrator ------------------------


def test_scorer_routes_through_calibrator() -> None:
    cal = fit_calibrator(_MISCALIBRATED, "isotonic")
    scorer = ExploitabilityScorer(calibrator=cal)
    f = ExploitFeatures(cvss=9.0, on_kev=True, reachable=True, has_public_exploit=True)
    raw = ExploitabilityScorer().raw_score(f)
    assert scorer.score(f) == cal.predict_one(raw)  # scorer defers to the calibrator


def test_verifier_scores_finding_through_calibrator(scope: Scope, audit: AuditLog) -> None:
    cal = fit_calibrator(_MISCALIBRATED, "isotonic")
    ctx = make_verify_ctx(scope, audit, _LfiSandbox(vulnerable=True))
    ctx.store.propose_finding(
        Finding(engagement_id=scope.engagement_id, asset="10.5.0.10",
                type="lfi", metadata={"param": "file"})
    )
    Verifier(default_oracle_registry(), ctx, calibrator=cal).run()
    verified = ctx.store.findings(FindingState.VERIFIED)[0]
    # LFI oracle confidence is 0.98; exploit_prob must be the *calibrated* value.
    assert verified.exploit_prob == round(cal.predict_one(0.98), 4)
