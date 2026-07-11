"""Ground-truth labels for the cyber range (spec §7, §9).

The range has *planted* vulnerabilities, so we know the correct answer. A label
is (asset, finding-type, exploitable?). Positives are the planted, exploitable
issues the engine should confirm; negatives are known-safe look-alikes that must
NOT be flagged (the false-positive traps — e.g. a patched version, an
internal-only theoretical CVE). Labels load from JSON so the eval set is
versioned alongside the range.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..schemas.common import StrictModel


class Label(StrictModel):
    asset: str
    type: str
    exploitable: bool
    note: str = ""

    def key(self) -> tuple[str, str]:
        return (self.asset, self.type)


class GroundTruth(StrictModel):
    name: str = "range"
    labels: tuple[Label, ...] = ()

    @classmethod
    def from_json(cls, path: str | Path) -> GroundTruth:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(data)

    def positives(self) -> set[tuple[str, str]]:
        return {label.key() for label in self.labels if label.exploitable}

    def negatives(self) -> set[tuple[str, str]]:
        return {label.key() for label in self.labels if not label.exploitable}

    def label_for(self, asset: str, type_: str) -> Label | None:
        return next(
            (label for label in self.labels if label.asset == asset and label.type == type_),
            None,
        )
