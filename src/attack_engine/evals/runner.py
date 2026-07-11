"""Eval runner — score an engagement's findings against ground truth (spec §9).

Given the confirmed findings from a run over the range and the ground-truth
labels, compute precision/recall (did we catch the planted vulns without
flagging the safe look-alikes?) and calibration (do the exploit probabilities
mean what they say?), then record the run to the configured tracker. This is the
yardstick the model bake-off and promotion gates are measured on.
"""

from __future__ import annotations

from ..schemas.common import StrictModel, iso_now
from ..schemas.findings import Finding, FindingState
from .dataset import GroundTruth
from .metrics import (
    CalibrationMetrics,
    ClassificationMetrics,
    calibration_metrics,
    classification_metrics,
)
from .tracking import NullTracker, Tracker


class EvalReport(StrictModel):
    name: str
    generated_at: str
    model_id: str | None = None
    precision: float
    recall: float
    f1: float
    brier: float
    ece: float
    tp: int
    fp: int
    fn: int
    tn: int
    n_calibration: int

    def as_metrics(self) -> dict[str, float]:
        return {
            "precision": self.precision, "recall": self.recall, "f1": self.f1,
            "brier": self.brier, "ece": self.ece,
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
        }

    def to_markdown(self) -> str:
        return (
            f"## Eval — {self.name}"
            + (f" (model `{self.model_id}`)" if self.model_id else "")
            + "\n\n"
            f"- Precision: **{self.precision:.2f}**  ·  Recall: **{self.recall:.2f}**  "
            f"·  F1: **{self.f1:.2f}**\n"
            f"- Confusion: TP={self.tp} FP={self.fp} FN={self.fn} TN={self.tn}\n"
            f"- Calibration: Brier={self.brier:.3f}  ·  ECE={self.ece:.3f}  "
            f"(n={self.n_calibration})\n"
        )


class EvalRunner:
    """Scores confirmed findings against a :class:`GroundTruth`."""

    def __init__(self, ground_truth: GroundTruth, *, tracker: Tracker | None = None) -> None:
        self._gt = ground_truth
        self._tracker = tracker or NullTracker()

    def evaluate(
        self, findings: list[Finding], *, name: str = "range-eval", model_id: str | None = None
    ) -> EvalReport:
        confirmed = [f for f in findings if f.state is FindingState.CONFIRMED]
        predicted = {(f.asset, f.type) for f in confirmed}
        by_key = {(f.asset, f.type): f for f in confirmed}

        classification: ClassificationMetrics = classification_metrics(
            predicted, self._gt.positives(), self._gt.negatives()
        )

        # Calibration: the engine's probability for each labelled item vs truth.
        pairs: list[tuple[float, int]] = []
        for label in self._gt.labels:
            finding = by_key.get(label.key())
            prob = finding.exploit_prob if (finding and finding.exploit_prob is not None) else 0.0
            pairs.append((float(prob), 1 if label.exploitable else 0))
        calibration: CalibrationMetrics = calibration_metrics(pairs)

        report = EvalReport(
            name=name,
            generated_at=iso_now(),
            model_id=model_id,
            precision=round(classification.precision, 4),
            recall=round(classification.recall, 4),
            f1=round(classification.f1, 4),
            brier=round(calibration.brier, 4),
            ece=round(calibration.ece, 4),
            tp=classification.tp, fp=classification.fp,
            fn=classification.fn, tn=classification.tn,
            n_calibration=calibration.n,
        )
        self._tracker.log_run(
            name, {"model_id": model_id or "baseline"}, report.as_metrics()
        )
        return report
