"""ATT&CK coverage matrix — an honest map of what the engine can do.

Given the technique library, reports per tactic which techniques are
``available`` (a real capability exists) vs ``planned`` (mapped, not yet built).
This is the professional artifact a regulated buyer expects: coverage grounded in
actual capabilities, not claims.
"""

from __future__ import annotations

from ..schemas.common import StrictModel
from .technique import TACTIC_ORDER, Tactic, TechniqueLibrary


class TacticCoverage(StrictModel):
    tactic: str          # display name
    tactic_id: str       # ATT&CK id
    available: list[str]  # "T1190 Exploit Public-Facing Application"
    planned: list[str]

    @property
    def total(self) -> int:
        return len(self.available) + len(self.planned)


class CoverageReport(StrictModel):
    tactics: list[TacticCoverage] = []
    available_count: int = 0
    planned_count: int = 0

    @property
    def total(self) -> int:
        return self.available_count + self.planned_count

    def to_markdown(self) -> str:
        lines = [
            "# ATT&CK Coverage",
            "",
            f"- Techniques mapped: {self.total}  ·  "
            f"available: **{self.available_count}**  ·  planned: {self.planned_count}",
            "",
            "| Tactic | Available | Planned |",
            "|---|---|---|",
        ]
        for tc in self.tactics:
            avail = ", ".join(tc.available) or "—"
            planned = ", ".join(tc.planned) or "—"
            lines.append(f"| **{tc.tactic}** ({tc.tactic_id}) | {avail} | {planned} |")
        return "\n".join(lines) + "\n"


def build_coverage(library: TechniqueLibrary) -> CoverageReport:
    """Build the per-tactic coverage matrix from the library."""

    tactics: list[TacticCoverage] = []
    avail_total = 0
    planned_total = 0
    for tactic in TACTIC_ORDER:
        techs = library.by_tactic(tactic)
        if not techs:
            continue
        available = [f"{t.id} {t.name}" for t in techs if t.available]
        planned = [f"{t.id} {t.name}" for t in techs if not t.available]
        avail_total += len(available)
        planned_total += len(planned)
        tactics.append(TacticCoverage(
            tactic=_display(tactic), tactic_id=tactic.value,
            available=available, planned=planned,
        ))
    return CoverageReport(
        tactics=tactics, available_count=avail_total, planned_count=planned_total,
    )


def _display(tactic: Tactic) -> str:
    return tactic.display
