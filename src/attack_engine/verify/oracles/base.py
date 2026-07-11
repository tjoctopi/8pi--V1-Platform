"""Oracle contract + registry (spec §5 — verification oracles).

An oracle is deterministic code that re-checks a *proposed* finding against the
target and returns a pass/fail verdict with evidence. Only a passed oracle can
promote a finding toward CONFIRMED (rule #1). Each oracle declares which finding
classes it handles; the registry routes a finding to the right one.

Oracles are versioned (``oracle_id`` includes a version, e.g.
``sqli_boolean_blind_oracle_v1``) so the audit trail records exactly which
verifier promoted a finding — reproducibility for regulated buyers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ...schemas.findings import Finding
from ..context import VerifyContext


@dataclass(frozen=True)
class OracleResult:
    """Verdict from one oracle run."""

    passed: bool
    oracle_id: str
    detail: str = ""
    #: Confidence in the verdict itself (independent of exploitability score).
    confidence: float = 1.0
    #: Audit ids / measurements substantiating the verdict.
    evidence: tuple[str, ...] = field(default_factory=tuple)
    #: Structured measurements (e.g. differential sizes) for the report.
    measurements: dict[str, object] = field(default_factory=dict)


class Oracle(ABC):
    """Deterministic confirmer for a class of findings."""

    #: Stable, versioned identifier recorded in the audit log.
    oracle_id: str

    @abstractmethod
    def handles(self, finding: Finding) -> bool:
        """Whether this oracle can verify ``finding``."""

    @abstractmethod
    def verify(self, finding: Finding, ctx: VerifyContext) -> OracleResult:
        """Re-check ``finding`` against the target and return a verdict."""


class OracleRegistry:
    """Routes a finding to the first oracle that handles it."""

    def __init__(self) -> None:
        self._oracles: list[Oracle] = []

    def register(self, oracle: Oracle) -> None:
        if not getattr(oracle, "oracle_id", ""):
            raise ValueError("oracle must define a non-empty oracle_id")
        self._oracles.append(oracle)

    def for_finding(self, finding: Finding) -> Oracle | None:
        return next((o for o in self._oracles if o.handles(finding)), None)

    def __len__(self) -> int:
        return len(self._oracles)
