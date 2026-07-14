"""Tests for the presentation builders (threat-map, attack-path, report).

Pure functions over console-shaped asset/finding dicts — no engine needed.
Assert the shapes the frontend tabs read so a real scan can never hand the
globe / force-graph a payload that crashes them.
"""

from __future__ import annotations

from attack_engine.api.views import (
    build_attack_path,
    build_report_summary,
    build_threat_map,
)

_ASSETS = [
    {
        "id": "a-1", "type": "webapp", "reachable": True, "exposure": "external",
        "identifiers": {"host": "juice.local", "ip": "10.5.0.10"},
        "versions": [{"product": "Node.js", "version": "18", "port": 3000}],
        "services": [{"port": 3000, "name": "http", "product": "Node.js", "version": "18"}],
    },
    {
        "id": "a-2", "type": "host", "reachable": True, "exposure": "unknown",
        "identifiers": {"host": None, "ip": "10.5.0.12"},
        "versions": [{"product": "vsftpd", "version": "2.3.4", "port": 21}],
        "services": [{"port": 21, "name": "ftp", "product": "vsftpd", "version": "2.3.4"}],
    },
]
# engine findings key off the host address, not the console asset id
_FINDINGS = [
    {"id": "f-1", "asset_id": "10.5.0.10", "title": "SQLi in /rest/products/search",
     "severity": "crit", "exploitability": "confirmed", "kev": False,
     "cve_refs": [], "technique_ref": "T1190"},
    {"id": "f-2", "asset_id": "10.5.0.12", "title": "vsftpd 2.3.4 backdoor",
     "severity": "high", "exploitability": "reachable", "kev": True,
     "cve_refs": ["CVE-2011-2523"], "technique_ref": "T1190"},
]


def test_threat_map_shape() -> None:
    tm = build_threat_map(_ASSETS, _FINDINGS)
    assert {"nodes", "edges", "layers", "risk"} <= tm.keys()
    ids = {n["id"] for n in tm["nodes"]}
    assert "edge" in ids and "a-1" in ids  # anchor + assets present
    a1 = next(n for n in tm["nodes"] if n["id"] == "a-1")
    assert a1["open_findings"] == 1
    assert a1["top_finding"]["severity"] == "crit"
    assert all({"source", "target"} <= e.keys() for e in tm["edges"])
    assert any(layer["key"] == "web" for layer in tm["layers"])
    assert {r["asset_id"] for r in tm["risk"]} == {"a-1", "a-2"}


def test_attack_path_shape_and_roles() -> None:
    ap = build_attack_path(_ASSETS, _FINDINGS)
    assert {"points", "arcs", "paths", "stats", "layer_stats", "continents"} <= ap.keys()
    # every point carries the globe fields
    for p in ap["points"]:
        assert {"id", "lat", "lng", "color", "role", "size"} <= p.keys()
        assert isinstance(p["lat"], (int, float)) and isinstance(p["lng"], (int, float))
    # a confirmed/high finding makes that host an entry foothold (keyed by address)
    assert "10.5.0.10" in ap["entry_points"]
    assert ap["stats"]["entry"] >= 1
    # paths carry steps the tab reads
    for path in ap["paths"]:
        assert {"id", "severity", "steps"} <= path.keys()
        for step in path["steps"]:
            assert {"geo", "technique", "severity"} <= step.keys()


def test_attack_path_empty_is_safe() -> None:
    ap = build_attack_path([], [])
    assert ap["points"] == [] and ap["paths"] == []
    assert ap["stats"] == {"entry": 0, "pivot": 0, "crown": 0, "paths": 0}


def test_report_summary_counts() -> None:
    s = build_report_summary(_FINDINGS, asset_count=2, audit_count=9, audit_valid=True)
    assert s["findings_total"] == 2
    assert s["assets"] == 2
    assert s["audit_chain_valid"] is True
    assert s["findings_open_by_severity"].get("crit") == 1
