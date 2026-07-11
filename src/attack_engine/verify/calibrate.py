"""Probability calibration (spec §5).

A model that says "0.9" should be right 90% of the time. Raw confidence scores
rarely are, so we calibrate against the ground-truth range: fit a mapping from
raw score → calibrated probability, then threshold promotion gates on the
*calibrated* value. Two standard methods, both pure-Python and deterministic:

* :class:`PlattCalibrator`   — logistic (sigmoid) fit; good with little data.
* :class:`IsotonicCalibrator`— monotonic step fit via pool-adjacent-violators;
  more flexible when enough labelled points exist.
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod

_EPS = 1e-6


def _sigmoid(x: float) -> float:
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


class Calibrator(ABC):
    fitted: bool = False

    @abstractmethod
    def fit(self, scores: list[float], labels: list[int]) -> Calibrator: ...

    @abstractmethod
    def predict_one(self, score: float) -> float: ...

    def predict(self, scores: list[float]) -> list[float]:
        return [self.predict_one(s) for s in scores]


class PlattCalibrator(Calibrator):
    """Sigmoid calibration ``p = σ(A·score + B)`` fit by gradient descent."""

    def __init__(self, lr: float = 0.5, iters: int = 3000) -> None:
        self.a = 1.0
        self.b = 0.0
        self._lr = lr
        self._iters = iters

    def fit(self, scores: list[float], labels: list[int]) -> PlattCalibrator:
        if len(scores) != len(labels):
            raise ValueError("scores and labels must be the same length")
        if not scores:
            raise ValueError("cannot fit on empty data")
        n = len(scores)
        for _ in range(self._iters):
            grad_a = grad_b = 0.0
            for s, y in zip(scores, labels, strict=True):
                p = _sigmoid(self.a * s + self.b)
                err = p - y
                grad_a += err * s
                grad_b += err
            self.a -= self._lr * grad_a / n
            self.b -= self._lr * grad_b / n
        self.fitted = True
        return self

    def predict_one(self, score: float) -> float:
        return min(1.0, max(0.0, _sigmoid(self.a * score + self.b)))


class IsotonicCalibrator(Calibrator):
    """Monotonic (non-decreasing) calibration via pool-adjacent-violators."""

    def __init__(self) -> None:
        # Parallel arrays: block boundary scores and their calibrated values.
        self._x: list[float] = []
        self._y: list[float] = []

    def fit(self, scores: list[float], labels: list[int]) -> IsotonicCalibrator:
        if len(scores) != len(labels):
            raise ValueError("scores and labels must be the same length")
        if not scores:
            raise ValueError("cannot fit on empty data")
        order = sorted(range(len(scores)), key=lambda i: scores[i])
        xs = [scores[i] for i in order]
        ys = [float(labels[i]) for i in order]

        # Each block: [weight, value, max_score].
        blocks: list[list[float]] = []
        for x, y in zip(xs, ys, strict=True):
            blocks.append([1.0, y, x])
            # Merge while the previous block's value exceeds this one's.
            while len(blocks) > 1 and blocks[-2][1] > blocks[-1][1]:
                w2, v2, _x2 = blocks.pop()
                w1, v1, x1 = blocks.pop()
                merged_w = w1 + w2
                merged_v = (w1 * v1 + w2 * v2) / merged_w
                blocks.append([merged_w, merged_v, max(x1, _x2)])

        self._x = [b[2] for b in blocks]
        self._y = [min(1.0, max(0.0, b[1])) for b in blocks]
        self.fitted = True
        return self

    def predict_one(self, score: float) -> float:
        if not self._x:
            raise RuntimeError("calibrator not fitted")
        # Step function: value of the last block whose boundary <= score.
        if score <= self._x[0]:
            return self._y[0]
        if score >= self._x[-1]:
            return self._y[-1]
        # Linear interpolation between adjacent block boundaries for smoothness.
        for i in range(1, len(self._x)):
            if score <= self._x[i]:
                x0, x1 = self._x[i - 1], self._x[i]
                y0, y1 = self._y[i - 1], self._y[i]
                if x1 == x0:
                    return y1
                frac = (score - x0) / (x1 - x0)
                return y0 + frac * (y1 - y0)
        return self._y[-1]
