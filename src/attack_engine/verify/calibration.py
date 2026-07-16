"""Calibration fitting + validation (spec §5) — making probabilities honest.

The calibrators in :mod:`attack_engine.verify.calibrate` were never fit in the
product, so a reported exploit probability was just a hand-tuned sigmoid. This
module closes that gap: it fits a calibrator to labelled ``(raw_score, outcome)``
samples (drawn from the range's ground truth and historical confirmed/refuted
findings) and reports the Brier/ECE *before vs after* so we can prove the mapping
actually improved calibration — "0.9" moving toward meaning right ~90% of the time.

Fitting is deterministic and pure-Python; the engine loads a samples file at
construction (config ``calibration_path``) and wires the fitted calibrator into
the scorer and the Verifier.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from ..logging import get_logger
from .calibrate import Calibrator, IsotonicCalibrator, PlattCalibrator

_log = get_logger("verify.calibration")

CalibrationMethod = Literal["isotonic", "platt"]

#: One labelled training point: a raw exploitability score and the true outcome.
Sample = tuple[float, int]


def load_calibration_samples(path: str | Path) -> list[Sample]:
    """Load ``[(score, label), …]`` from a JSON ``{"samples": [{score,label}]}`` file."""

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    samples: list[Sample] = []
    for row in data.get("samples", []):
        score = float(row["score"])
        label = int(row["label"])
        if label not in (0, 1):
            raise ValueError(f"calibration label must be 0 or 1, got {label!r}")
        samples.append((score, label))
    if not samples:
        raise ValueError(f"no calibration samples in {path}")
    return samples


def fit_calibrator(samples: list[Sample], method: CalibrationMethod = "isotonic") -> Calibrator:
    """Fit a calibrator of the requested family to labelled samples."""

    scores = [s for s, _ in samples]
    labels = [y for _, y in samples]
    calibrator: Calibrator = (
        IsotonicCalibrator() if method == "isotonic" else PlattCalibrator()
    )
    calibrator.fit(scores, labels)
    _log.info("fitted calibrator", method=method, n=len(samples))
    return calibrator


def calibration_report(calibrator: Calibrator, samples: list[Sample]) -> dict[str, Any]:
    """Brier/ECE of the raw scores vs the calibrated scores on ``samples``.

    ``improved`` is True when calibration lowered ECE — the check that fitting
    was worthwhile rather than cosmetic.
    """

    # Lazy import keeps the verify package from pulling the whole evals package.
    from ..evals.metrics import calibration_metrics

    labels = [y for _, y in samples]
    raw_pairs = [(s, y) for s, y in samples]
    cal_pairs = list(zip(calibrator.predict([s for s, _ in samples]), labels, strict=True))
    before = calibration_metrics(raw_pairs)
    after = calibration_metrics(cal_pairs)
    return {
        "n": len(samples),
        "before": before.as_dict(),
        "after": after.as_dict(),
        "improved": after.ece <= before.ece,
    }
