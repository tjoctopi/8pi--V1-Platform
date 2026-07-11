"""Calibrated Bayesian exploitability scoring (spec §5).

We prioritise by a *calibrated exploitability probability*, not raw CVSS. A
logistic model combines the signals that actually predict exploitation —
known-exploited (KEV), reachability from the entry point, public exploit
availability, and CVSS as one input among several — into a raw probability,
which an optional fitted :class:`~attack_engine.verify.calibrate.Calibrator`
maps onto the range's ground truth so "0.9" means right ~90% of the time.

Reachability gates priority hard: an unreachable ("internal-only theoretical")
finding is deprioritised automatically regardless of CVSS — the exact behaviour
the spec calls for.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from ..schemas.findings import Priority
from ..verify.calibrate import Calibrator


@dataclass(frozen=True)
class ExploitFeatures:
    cvss: float = 0.0  # 0..10
    on_kev: bool = False
    reachable: bool = False
    has_public_exploit: bool = False


# Logistic weights (log-odds space). Tuned so KEV + reachable + public-exploit
# dominates, CVSS contributes but cannot alone push a finding to "patch now".
_W_INTERCEPT = -3.2
_W_CVSS = 3.0        # applied to cvss/10
_W_KEV = 2.6
_W_REACHABLE = 1.8
_W_EXPLOIT = 1.4


def _sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    z = math.exp(x)
    return z / (1.0 + z)


class ExploitabilityScorer:
    """Turns features into a calibrated probability and a priority band."""

    def __init__(self, calibrator: Calibrator | None = None) -> None:
        self._calibrator = calibrator

    def raw_score(self, f: ExploitFeatures) -> float:
        z = (
            _W_INTERCEPT
            + _W_CVSS * (min(10.0, max(0.0, f.cvss)) / 10.0)
            + _W_KEV * (1.0 if f.on_kev else 0.0)
            + _W_REACHABLE * (1.0 if f.reachable else 0.0)
            + _W_EXPLOIT * (1.0 if f.has_public_exploit else 0.0)
        )
        return _sigmoid(z)

    def score(self, f: ExploitFeatures) -> float:
        raw = self.raw_score(f)
        if self._calibrator is not None and getattr(self._calibrator, "fitted", False):
            return self._calibrator.predict_one(raw)
        return raw

    @staticmethod
    def priority(prob: float, *, on_kev: bool, reachable: bool) -> Priority:
        # Reachability gates hard: internal-only theoretical → deprioritised.
        if not reachable:
            return Priority.INFORMATIONAL
        if on_kev and prob >= 0.8:
            return Priority.PATCH_IMMEDIATELY
        if prob >= 0.7:
            return Priority.HIGH
        if prob >= 0.4:
            return Priority.MEDIUM
        return Priority.LOW
