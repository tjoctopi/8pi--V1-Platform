"""Tests for the presentation builders (threat-map, attack-path, report).

Pure functions over console-shaped asset/finding dicts — no engine needed.
Assert the shapes the frontend tabs read so a real scan can never hand the
globe / force-graph a payload that crashes them.
"""

from __future__ import annotations

from attack_engine.api.views import (
    build_attack_path,
    build_attack_tree,
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
    assert ap["stats"] == {"entry": 0, "pivot": 0, "crown": 0, "paths": 0, "chains": 0}


def test_attack_path_renders_engine_chains_as_multihop_routes() -> None:
    # A confirmed web-RCE chain (cmdi→foothold) becomes a real multi-hop route,
    # ranked ahead of flat per-finding paths, with per-hop ATT&CK techniques.
    assets = [{"id": "a1", "type": "webapp", "reachable": True,
               "identifiers": {"ip": "10.5.0.12"}, "exposure": "external"}]
    chains = [{
        "id": "c1", "objective": "web foothold via cmdi→RCE",
        "entry": "http://10.5.0.12:80/mutillidae/index.php?page",
        "confirmed_depth": 2, "is_realised": True,
        "steps": [
            {"order": 0, "kind": "cmdi",
             "subject": "http://10.5.0.12:80/mutillidae/index.php?page", "confirmed": True},
            {"order": 1, "kind": "foothold",
             "subject": "http://10.5.0.12:80/mutillidae/index.php?page", "confirmed": True},
        ],
    }]
    ap = build_attack_path(assets, [], chains=chains)
    assert ap["stats"]["chains"] == 1
    route = ap["paths"][0]  # chain route leads
    assert route["kind"] == "chain" and route["is_realised"] is True
    assert [s["role"] for s in route["steps"]] == ["entry", "crown"]
    assert route["steps"][0]["technique"]["id"] == "T1059"  # cmdi → command exec
    assert route["steps"][0]["exploitability"] == "confirmed"


def test_attack_path_stats_match_entry_and_crown_lists() -> None:
    # regression: stats tallies must equal the id lists they summarise (no drift
    # from the crown-ensure flip) — stats.entry === len(entry_points), etc.
    assets = [
        {"id": "a1", "type": "webapp", "reachable": True, "exposure": "external",
         "identifiers": {"ip": "10.5.0.12"}},
        {"id": "a2", "type": "host", "reachable": True, "exposure": "internal",
         "identifiers": {"ip": "10.5.0.20"}},
    ]
    findings = [
        {"id": "f1", "asset_id": "10.5.0.12", "severity": "high", "exploitability": "confirmed"},
        {"id": "f2", "asset_id": "10.5.0.20", "severity": "low", "exploitability": "unconfirmed"},
    ]
    ap = build_attack_path(assets, findings)
    assert ap["stats"]["entry"] == len(ap["entry_points"])
    assert ap["stats"]["crown"] == len(ap["crown_jewels"])


def test_attack_path_renders_domain_admin_route() -> None:
    ap = build_attack_path(
        [{"id": "dc", "type": "host", "identifiers": {"ip": "10.5.0.20"}}],
        [],
        ad_paths=[{"start": "ALICE", "target": "DOMAIN ADMINS",
                   "techniques": ["T1098", "T1003.006"]}],
    )
    assert ap["stats"]["chains"] == 1
    route = ap["paths"][0]
    assert route["kind"] == "identity" and route["crown_id"] == "DOMAIN ADMINS"
    assert route["steps"][0]["role"] == "entry" and route["steps"][-1]["role"] == "crown"


# ── attack tree (kill-chain hierarchy) ───────────────────────────────────────

def _node(tree: dict, node_id: str) -> dict:
    return next(n for n in tree["nodes"] if n["id"] == node_id)


def test_attack_tree_empty_is_safe() -> None:
    t = build_attack_tree([], [])
    assert t["nodes"] == [{**_node(t, "origin")}]  # only the origin root
    assert t["edges"] == []
    assert next(p["key"] for p in t["phases"]) == "origin"
    assert t["summary"]["live_footholds"] == 0


def test_attack_tree_builds_full_breach_lineage() -> None:
    # origin → recon(asset) → initial-access(cmdi) → foothold(session) →
    # post-ex(loot) → escalate(owned) → objective(DA): the whole breach story.
    assets = [{"id": "a", "type": "host", "reachable": True, "exposure": "external",
               "identifiers": {"ip": "10.5.0.12"}}]
    findings = [{"id": "f1", "asset_id": "10.5.0.12", "type": "command-injection",
                 "title": "cmdi on target_host", "severity": "crit", "cvss": 9.8,
                 "exploitability": "confirmed", "status": "confirmed",
                 "technique_ref": "T1059", "cve_refs": [], "remediation": "no shell",
                 "reachability_reason": "proven by live probe"}]
    sessions = [{"id": "s1", "host": "10.5.0.12", "status": "active", "technique": "T1190",
                 "proof": {"whoami": "www-data", "hostname": "box"},
                 "loot": [{"command": "id", "output": "uid=33(www-data)"}],
                 "site_content": {"url": "http://10.5.0.12/", "status": 200,
                                  "snippet": "Metasploitable2"}, "kind": "shell"}]
    t = build_attack_tree(
        assets, findings, sessions=sessions,
        ad_paths=[{"start": "alice", "target": "Domain Admins", "techniques": ["T1098"]}],
        world_model={"owned_principals": ["alice"]},
    )
    phases = {n["id"]: n["phase"] for n in t["nodes"]}
    assert phases["asset-10.5.0.12"] == "recon"
    assert phases["find-f1"] == "initial-access"
    assert phases["sess-s1"] == "foothold"
    assert phases["loot-s1"] == "post-ex"
    assert phases["objective-ad-0"] == "objective"

    # confirmed cmdi is solid; carries impact for the detail panel
    fnode = _node(t, "find-f1")
    assert fnode["status"] == "confirmed" and fnode["cvss"] == 9.8
    assert fnode["detail"]["remediation"] == "no shell"

    # the foothold node carries proof; the loot node carries the captured showcase
    assert _node(t, "sess-s1")["label"] == "www-data@10.5.0.12"
    loot = _node(t, "loot-s1")["detail"]
    assert loot["loot"][0]["command"] == "id"
    assert loot["site_content"]["snippet"] == "Metasploitable2"

    # lineage edges exist end-to-end, and edges are unique
    pairs = {(e["source"], e["target"]) for e in t["edges"]}
    assert len(pairs) == len(t["edges"])  # no duplicates
    for pair in [("origin", "asset-10.5.0.12"), ("asset-10.5.0.12", "find-f1"),
                 ("find-f1", "sess-s1"), ("sess-s1", "loot-s1"),
                 ("own-0", "objective-ad-0")]:
        assert pair in pairs, pair

    assert t["summary"] == {"entry_points": 1, "confirmed_findings": 1,
                            "live_footholds": 1, "crown_reached": 1, "domain_admin": True}


def test_attack_tree_caps_potential_candidates_with_summary_node() -> None:
    # A thorough crawl can graduate many low-confidence candidates; the tree stays
    # readable by capping unconfirmed nodes and folding the rest into one honest
    # "+N more" node (never silently dropped).
    assets = [{"id": "a", "type": "webapp", "reachable": True,
               "identifiers": {"ip": "10.5.0.11"}}]
    findings = [
        {"id": f"c{i}", "asset_id": "10.5.0.11", "type": "sqli-boolean-blind",
         "title": f"candidate {i}", "severity": "med", "exploitability": "reachable",
         "status": "proposed", "technique_ref": "T1190", "cve_refs": []}
        for i in range(25)
    ]
    t = build_attack_tree(assets, findings)
    ia = [n for n in t["nodes"] if n["phase"] == "initial-access"]
    more = [n for n in ia if n["id"] == "find-more"]
    assert more, "expected a '+N more' summary node"
    assert "15 more" in more[0]["label"]  # 25 candidates, cap 10, 15 folded
    assert len([n for n in ia if n["id"] != "find-more"]) == 10


def test_attack_tree_marks_unconfirmed_as_potential() -> None:
    # A reachable-but-unconfirmed finding is dashed (status != confirmed).
    assets = [{"id": "a", "type": "webapp", "reachable": True,
               "identifiers": {"ip": "10.5.0.11"}}]
    findings = [{"id": "f2", "asset_id": "10.5.0.11", "type": "sqli-boolean-blind",
                 "title": "maybe sqli", "severity": "high", "exploitability": "reachable",
                 "status": "proposed", "technique_ref": "T1190", "cve_refs": []}]
    t = build_attack_tree(assets, findings)
    assert _node(t, "find-f2")["status"] == "reachable"
    assert t["summary"]["confirmed_findings"] == 0
    assert t["summary"]["live_footholds"] == 0


def test_report_summary_counts() -> None:
    s = build_report_summary(_FINDINGS, asset_count=2, audit_count=9, audit_valid=True)
    assert s["findings_total"] == 2
    assert s["assets"] == 2
    assert s["audit_chain_valid"] is True
    assert s["findings_open_by_severity"].get("crit") == 1
