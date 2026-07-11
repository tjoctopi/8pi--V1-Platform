"""NVD + CISA-KEV ingest (spec §9 Sprint 3 — real feeds behind the interface).

Parses the **NVD 2.0** vulnerability JSON and the **CISA KEV** catalog into the
engine's :class:`~attack_engine.correlate.feeds.CveRecord` model, mapping CPE
``cpeMatch`` ranges onto correct version intervals (the whole point — no naive
string matching). The parsing is pure and fixture-tested; the network fetch is a
thin, separately-invoked wrapper (an integration concern, never hit in tests).

CPE 2.3 criteria look like::

    cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
             ^part ^vendor ^product ^version
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..versioning import VersionRange
from .feeds import AffectedProduct, CveRecord, LocalCveFeed


def _cpe_parts(criteria: str) -> tuple[str, str, str]:
    """Return (vendor, product, version) from a CPE 2.3 string."""

    parts = criteria.split(":")
    # cpe:2.3:part:vendor:product:version:...
    vendor = parts[3] if len(parts) > 3 else ""
    product = parts[4] if len(parts) > 4 else ""
    version = parts[5] if len(parts) > 5 else "*"
    return vendor, product, version


def _affected_from_cpe_match(cpe_match: dict[str, Any]) -> AffectedProduct | None:
    criteria = cpe_match.get("criteria", "")
    if not criteria:
        return None
    vendor, product, version = _cpe_parts(criteria)
    if not product:
        return None
    human = product.replace("_", " ")
    aliases = tuple(
        dict.fromkeys(
            a for a in (vendor, human, f"{vendor} {human}", f"{vendor} {product}") if a
        )
    )

    start_incl = cpe_match.get("versionStartIncluding")
    start_excl = cpe_match.get("versionStartExcluding")
    end_incl = cpe_match.get("versionEndIncluding")
    end_excl = cpe_match.get("versionEndExcluding")

    ranges: tuple[VersionRange, ...]
    if any((start_incl, start_excl, end_incl, end_excl)):
        ranges = (
            VersionRange.build(
                # NVD start-excluding has no exact interval primitive here; we
                # approximate with the included bound (documented limitation).
                introduced=start_incl or start_excl,
                fixed=end_excl,
                last_affected=None if end_excl else end_incl,
            ),
        )
    elif version and version != "*":
        # An exact vulnerable version pinned in the CPE itself.
        ranges = (VersionRange.build(introduced=version, last_affected=version),)
    else:
        ranges = ()  # all versions of the product

    return AffectedProduct(product=human, aliases=aliases, ranges=ranges)


def _first_cvss(metrics: dict[str, Any]) -> float:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            return float(data.get("baseScore", 0.0))
    return 0.0


def parse_nvd(doc: dict[str, Any]) -> list[CveRecord]:
    """Parse an NVD 2.0 response document into CVE records."""

    records: list[CveRecord] = []
    for item in doc.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        descriptions = cve.get("descriptions", [])
        description = next(
            (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
            "",
        )
        cwe = None
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("value", "").startswith("CWE-"):
                    cwe = desc["value"]
                    break
            if cwe:
                break

        affected: list[AffectedProduct] = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if not cpe_match.get("vulnerable", True):
                        continue
                    ap = _affected_from_cpe_match(cpe_match)
                    if ap is not None:
                        affected.append(ap)

        records.append(
            CveRecord(
                id=cve_id,
                description=description,
                cvss=_first_cvss(cve.get("metrics", {})),
                kev=False,  # set from the KEV catalog in build_feed
                cwe=cwe,
                has_public_exploit=False,
                affected=tuple(affected),
            )
        )
    return records


def parse_kev(doc: dict[str, Any]) -> set[str]:
    """Parse the CISA KEV catalog into a set of known-exploited CVE ids."""

    return {v["cveID"] for v in doc.get("vulnerabilities", []) if v.get("cveID")}


def build_feed(nvd_doc: dict[str, Any], kev_doc: dict[str, Any]) -> LocalCveFeed:
    """Merge NVD records with the KEV catalog into a queryable feed."""

    kev = parse_kev(kev_doc)
    records = parse_nvd(nvd_doc)
    merged = [
        r.__class__(
            id=r.id, description=r.description, cvss=r.cvss,
            kev=r.id in kev, cwe=r.cwe,
            has_public_exploit=r.id in kev,  # KEV ⇒ exploited in the wild
            affected=r.affected,
        )
        for r in records
    ]
    return LocalCveFeed(merged)


def build_feed_from_files(nvd_path: str | Path, kev_path: str | Path) -> LocalCveFeed:
    """Build a feed from cached NVD + KEV JSON files (offline; the prod path)."""

    nvd_doc = json.loads(Path(nvd_path).read_text(encoding="utf-8"))
    kev_doc = json.loads(Path(kev_path).read_text(encoding="utf-8"))
    return build_feed(nvd_doc, kev_doc)


# --- live fetch (integration only; never exercised by the test suite) ---------

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_json(url: str, *, timeout: int = 30) -> dict[str, Any]:  # pragma: no cover
    """Fetch a JSON document over HTTPS. Network — integration use only."""

    import urllib.request

    with urllib.request.urlopen(url, timeout=timeout) as resp:
        doc: dict[str, Any] = json.loads(resp.read().decode("utf-8"))
    return doc
