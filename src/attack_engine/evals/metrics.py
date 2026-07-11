"""Accuracy & calibration metrics (spec §5 — "accuracy-first", §9 eval).

Pure, dependency-free metric functions so the engine's precision/recall and
probability *calibration* can be measured against the ground-truth range. These
back the promotion gates ("threshold on calibrated precision") and the model
bake-off ("swap the model once it beats the baseline on the eval").
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ClassificationMetrics:
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def as_dict(self) -> dict[str, float]:
        return {
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


def classification_metrics(
    predicted: set[tuple[str, str]],
    positives: set[tuple[str, str]],
    negatives: set[tuple[str, str]],
) -> ClassificationMetrics:
    """Confusion matrix from predicted vs ground-truth positive/negative sets.

    ``predicted`` is what the engine flagged (e.g. confirmed, actionable);
    ``positives`` are truly-exploitable planted items; ``negatives`` are
    known-safe items that must NOT be flagged (false-positive sources).
    """

    tp = len(predicted & positives)
    fp = len(predicted & negatives) + len(predicted - positives - negatives)
    fn = len(positives - predicted)
    tn = len(negatives - predicted)
    return ClassificationMetrics(tp=tp, fp=fp, fn=fn, tn=tn)


@dataclass(frozen=True)
class ReliabilityBin:
    lower: float
    upper: float
    count: int
    avg_predicted: float
    fraction_positive: float


@dataclass(frozen=True)
class CalibrationMetrics:
    brier: float
    ece: float  # expected calibration error
    n: int
    bins: list[ReliabilityBin] = field(default_factory=list)

    def as_dict(self) -> dict[str, float]:
        return {"brier": round(self.brier, 4), "ece": round(self.ece, 4), "n": self.n}


def calibration_metrics(
    pairs: list[tuple[float, int]], *, n_bins: int = 10
) -> CalibrationMetrics:
    """Brier score + expected calibration error over (predicted_prob, label) pairs.

    A lower Brier and ECE mean the probabilities are better calibrated — "0.9"
    actually meaning right ~90% of the time.
    """

    if not pairs:
        return CalibrationMetrics(brier=0.0, ece=0.0, n=0, bins=[])

    n = len(pairs)
    brier = sum((p - y) ** 2 for p, y in pairs) / n

    bins: list[ReliabilityBin] = []
    ece = 0.0
    for i in range(n_bins):
        lo = i / n_bins
        hi = (i + 1) / n_bins
        # Last bin is closed on the right so p == 1.0 is included.
        members = [
            (p, y) for p, y in pairs
            if (lo <= p < hi) or (i == n_bins - 1 and p == 1.0)
        ]
        if not members:
            continue
        count = len(members)
        avg_pred = sum(p for p, _ in members) / count
        frac_pos = sum(y for _, y in members) / count
        ece += (count / n) * abs(avg_pred - frac_pos)
        bins.append(
            ReliabilityBin(
                lower=lo, upper=hi, count=count,
                avg_predicted=round(avg_pred, 4), fraction_positive=round(frac_pos, 4),
            )
        )
    return CalibrationMetrics(brier=brier, ece=ece, n=n, bins=bins)
