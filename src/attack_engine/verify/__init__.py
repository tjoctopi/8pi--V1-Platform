"""Verification Layer — deterministic oracles + fusion + calibration (spec §5).

Kills false positives. Only a passed oracle promotes a finding (rule #1). This
package is the accuracy engine: oracles re-check proposals, fusion combines
independent signals, and calibration makes probabilities mean what they say.
"""

from __future__ import annotations

from .calibrate import Calibrator, IsotonicCalibrator, PlattCalibrator
from .context import VerifyContext
from .fusion import Evidence, agreement_boost, fuse
from .oracles import (
    Oracle,
    OracleRegistry,
    OracleResult,
    SqliBooleanBlindOracle,
    VersionRegrabOracle,
    default_oracle_registry,
)
from .verifier import Verifier, VerifyReport

__all__ = [
    "VerifyContext",
    "Verifier",
    "VerifyReport",
    "Oracle",
    "OracleRegistry",
    "OracleResult",
    "VersionRegrabOracle",
    "SqliBooleanBlindOracle",
    "default_oracle_registry",
    "Evidence",
    "fuse",
    "agreement_boost",
    "Calibrator",
    "PlattCalibrator",
    "IsotonicCalibrator",
]
