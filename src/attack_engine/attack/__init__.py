"""MITRE ATT&CK technique library + coverage (O4).

The offensive breadth of the platform is expressed as ATT&CK techniques, each a
first-class, versioned entry mapped to the concrete engine capability that
performs (or confirms) it. Adding a technique — not new agent code — is how
breadth grows. The library is the single source of truth for technique ids used
across the kill-chain planner, the intelligence dossier, and adversary profiles,
and it backs an honest per-tactic coverage matrix (what we can actually do vs.
what is still planned).
"""

from __future__ import annotations

from .catalog import TECHNIQUE_BY_FINDING_TYPE, build_library, technique_for_finding_type
from .coverage import CoverageReport, TacticCoverage, build_coverage
from .technique import (
    CapabilityKind,
    Tactic,
    Technique,
    TechniqueCapability,
    TechniqueLibrary,
)

__all__ = [
    "Tactic",
    "Technique",
    "TechniqueCapability",
    "CapabilityKind",
    "TechniqueLibrary",
    "build_library",
    "TECHNIQUE_BY_FINDING_TYPE",
    "technique_for_finding_type",
    "CoverageReport",
    "TacticCoverage",
    "build_coverage",
]
