"""Correlation — the Exploitability Matcher (spec §3 step 4, §5).

Maps confirmed services to CVE/KEV with correct interval version matching,
computes reachability from the attack graph, and assigns a calibrated Bayesian
exploitability probability + priority — not raw CVSS.
"""

from __future__ import annotations

from .feeds import AffectedProduct, CveFeed, CveRecord, LocalCveFeed
from .matcher import ExploitabilityMatcher, MatchReport
from .scoring import ExploitabilityScorer, ExploitFeatures

__all__ = [
    "ExploitabilityMatcher",
    "MatchReport",
    "ExploitabilityScorer",
    "ExploitFeatures",
    "CveFeed",
    "CveRecord",
    "AffectedProduct",
    "LocalCveFeed",
]
