"""CVE / KEV feeds with correct interval version matching (spec §5).

A feed answers: "which CVEs affect product P at version V?" — using proper
version intervals, not string matching (the #1 false-positive source). The
:class:`CveFeed` protocol lets a real NVD+CISA-KEV ingest slot in later; Sprint 1
ships a :class:`LocalCveFeed` seeded from a bundled JSON file so the correlator
(and its tests) run fully offline.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ..versioning import VersionRange

_SEED_PATH = Path(__file__).parent / "data" / "cve_seed.json"


@dataclass(frozen=True)
class AffectedProduct:
    product: str
    aliases: tuple[str, ...] = ()
    ranges: tuple[VersionRange, ...] = ()  # empty = all versions affected

    def matches(self, product: str, version: str | None) -> bool:
        names = {self.product.lower(), *(a.lower() for a in self.aliases)}
        p = product.lower().strip()
        if not any(p == n or n in p or p in n for n in names):
            return False
        if not self.ranges:
            return True  # product affected at all versions
        if version is None:
            return False  # a versioned CVE needs a version to match (avoid FP)
        return any(r.contains(version) for r in self.ranges)


@dataclass(frozen=True)
class CveRecord:
    id: str
    description: str = ""
    cvss: float = 0.0
    kev: bool = False
    cwe: str | None = None
    has_public_exploit: bool = False
    affected: tuple[AffectedProduct, ...] = field(default_factory=tuple)

    def affects(self, product: str, version: str | None) -> bool:
        return any(a.matches(product, version) for a in self.affected)


class CveFeed(Protocol):
    def match(self, product: str, version: str | None) -> list[CveRecord]: ...
    def is_kev(self, cve_id: str) -> bool: ...


class LocalCveFeed:
    """In-memory feed loaded from a JSON file (offline; used by default)."""

    def __init__(self, records: list[CveRecord]) -> None:
        self._records = records
        self._kev = {r.id for r in records if r.kev}

    @classmethod
    def from_json(cls, path: str | Path | None = None) -> LocalCveFeed:
        data = json.loads(Path(path or _SEED_PATH).read_text(encoding="utf-8"))
        records = [cls._parse_record(r) for r in data.get("records", [])]
        return cls(records)

    @staticmethod
    def _parse_record(r: dict[str, Any]) -> CveRecord:
        affected = []
        for a in r.get("affected", []):
            ranges = tuple(
                VersionRange.build(
                    introduced=rng.get("introduced"),
                    fixed=rng.get("fixed"),
                    last_affected=rng.get("last_affected"),
                )
                for rng in a.get("ranges", [])
            )
            affected.append(
                AffectedProduct(
                    product=a["product"],
                    aliases=tuple(a.get("aliases", [])),
                    ranges=ranges,
                )
            )
        return CveRecord(
            id=r["id"],
            description=r.get("description", ""),
            cvss=float(r.get("cvss", 0.0)),
            kev=bool(r.get("kev", False)),
            cwe=r.get("cwe"),
            has_public_exploit=bool(r.get("has_public_exploit", False)),
            affected=tuple(affected),
        )

    def match(self, product: str, version: str | None) -> list[CveRecord]:
        return [r for r in self._records if r.affects(product, version)]

    def is_kev(self, cve_id: str) -> bool:
        return cve_id in self._kev
