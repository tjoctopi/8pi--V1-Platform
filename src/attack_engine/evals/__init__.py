"""Evaluation harness — precision/recall + calibration vs ground truth (spec §9)."""

from __future__ import annotations

from .dataset import GroundTruth, Label
from .metrics import (
    CalibrationMetrics,
    ClassificationMetrics,
    calibration_metrics,
    classification_metrics,
)
from .runner import EvalReport, EvalRunner
from .tracking import LocalJsonTracker, NullTracker, Tracker

__all__ = [
    "GroundTruth",
    "Label",
    "EvalRunner",
    "EvalReport",
    "classification_metrics",
    "calibration_metrics",
    "ClassificationMetrics",
    "CalibrationMetrics",
    "Tracker",
    "NullTracker",
    "LocalJsonTracker",
]
