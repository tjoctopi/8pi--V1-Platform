"""Presentation builders — engine data → the console's richer view payloads.

The threat-map (force graph) and attack-path (globe) tabs need shapes the engine
doesn't produce directly: layer classification, per-asset risk, and — for the
globe — a geographic-ish projection. Those are *presentation* concerns, so they
live here rather than in the engine. Everything is derived deterministically
from the already-translated console asset/finding dicts (see
:mod:`attack_engine.api.serialize`), so the same real scan drives every view.
"""

from __future__ import annotations

import hashlib
import math
from itertools import pairwise
from typing import Any

# ── shared palette (matches frontend/tailwind.config.js) ──────────────────────
_VOLT = "#FF00A0"      # external / high
_INFO = "#00E5FF"      # web / low
_WHITE = "#FFFFFF"     # host
_MUTED = "#7A7A7A"     # service
_INCIDENT = "#FF2A2A"  # crit
_WARN = "#FFB020"      # med

_SEV_RISK = {"crit": 95, "high": 80, "med": 55, "low": 30, "info": 12}
_SEV_ORDER = {"crit": 0, "high": 1, "med": 2, "low": 3, "info": 4}

_LAYERS = {
    "external": {"label": "External / Edge", "color": _VOLT},
    "web": {"label": "Web Apps", "color": _INFO},
    "host": {"label": "Hosts", "color": _WHITE},
    "service": {"label": "Services", "color": _MUTED},
    "identity": {"label": "Identity / AD", "color": _INCIDENT},
}


def _asset_label(a: dict[str, Any]) -> str:
    ident = a.get("identifiers") or {}
    label = ident.get("host") or ident.get("ip") or ident.get("url") or a.get("id")
    return str(label or "asset")


def _asset_layer(a: dict[str, Any]) -> str:
    return "web" if a.get("type") == "webapp" else "host"


def _asset_addr(a: dict[str, Any]) -> str:
    """The address findings reference (engine findings key off the host address,
    not the console asset id)."""
    ident = a.get("identifiers") or {}
    return str(ident.get("ip") or ident.get("host") or a.get("id") or "")


def _findings_by_asset(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    by: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        by.setdefault(f.get("asset_id") or "", []).append(f)
    return by


def _top_finding(fs: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not fs:
        return None
    top = sorted(fs, key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 9))[0]
    return {
        "title": top.get("title"),
        "severity": top.get("severity"),
        "exploitability": top.get("exploitability"),
        "kev": top.get("kev"),
        "cve_refs": top.get("cve_refs") or [],
    }


def _asset_risk(fs: list[dict[str, Any]], reachable: bool) -> int:
    if fs:
        return max(_SEV_RISK.get(f.get("severity", "info"), 10) for f in fs)
    return 15 if reachable else 6


# ── threat map (force graph) ──────────────────────────────────────────────────

def build_threat_map(
    assets: list[dict[str, Any]], findings: list[dict[str, Any]]
) -> dict[str, Any]:
    by_asset = _findings_by_asset(findings)
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    risk: list[dict[str, Any]] = []

    # an edge/internet anchor so external assets have something to hang off
    nodes.append({
        "id": "edge", "label": "Internet / Edge", "type": "edge", "parent": None,
        "layer": "external", "layer_color": _LAYERS["external"]["color"],
        "layer_label": _LAYERS["external"]["label"], "risk": 0, "exposure": "external",
        "product": None, "version": None, "port": None, "open_findings": 0,
        "top_finding": None,
    })

    for a in assets:
        fs = by_asset.get(_asset_addr(a), [])
        svc = (a.get("services") or [{}])[0] if a.get("services") else {}
        layer = _asset_layer(a)
        r = _asset_risk(fs, a.get("reachable", False))
        nodes.append({
            "id": a["id"], "label": _asset_label(a), "type": a.get("type", "host"),
            "parent": "edge",
            "layer": layer, "layer_color": _LAYERS[layer]["color"],
            "layer_label": _LAYERS[layer]["label"], "risk": r,
            "exposure": a.get("exposure", "unknown"),
            "product": (svc or {}).get("product"),
            "version": (svc or {}).get("version"),
            "port": (a.get("versions") or [{}])[0].get("port") if a.get("versions") else None,
            "open_findings": len(fs),
            "top_finding": _top_finding(fs),
        })
        edges.append({"source": "edge", "target": a["id"], "relation": "reaches"})
        risk.append({"asset_id": a["id"], "score": r})

        # one service node per open service, for depth
        for s in a.get("services") or []:
            sid = f"{a['id']}:{s.get('port')}"
            nodes.append({
                "id": sid, "label": f"{s.get('name') or 'svc'}/{s.get('port')}",
                "type": "service", "parent": a["id"],
                "layer": "service", "layer_color": _LAYERS["service"]["color"],
                "layer_label": _LAYERS["service"]["label"], "risk": max(10, r - 20),
                "exposure": a.get("exposure", "unknown"),
                "product": s.get("product"), "version": s.get("version"),
                "port": s.get("port"), "open_findings": 0, "top_finding": None,
            })
            edges.append({"source": a["id"], "target": sid, "relation": "runs"})

    # layer summary
    layers = []
    for key, meta in _LAYERS.items():
        members = [n for n in nodes if n["layer"] == key]
        if not members:
            continue
        layers.append({
            "key": key, "label": meta["label"], "color": meta["color"],
            "count": len(members),
            "external": sum(1 for n in members if n["exposure"] == "external"),
            "findings": sum(n["open_findings"] for n in members),
            "risk": max((n["risk"] for n in members), default=0),
        })

    return {"nodes": nodes, "edges": edges, "layers": layers, "risk": risk}


# ── attack path (globe) ────────────────────────────────────────────────────────

def _geo_for(index: int, total: int) -> tuple[float, float]:
    """Deterministic lat/lng spread so assets plot legibly on the globe."""

    total = max(total, 1)
    angle = (index / total) * 2 * math.pi
    lat = round(28 * math.sin(angle) + (index % 3) * 6 - 6, 3)
    lng = round(-40 + (index / total) * 120 + 10 * math.cos(angle), 3)
    return lat, lng


#: The operator/attacker origin the breach arcs emanate from (config later).
ATTACKER_ORIGIN = (40.7128, -74.006)  # NYC — a neutral ops vantage


def _is_private_ip(addr: str) -> bool:
    parts = addr.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return False  # hostname / non-IPv4 → treated as external
    a, b = int(parts[0]), int(parts[1])
    return (a == 10 or a == 127 or (a == 192 and b == 168)
            or (a == 172 and 16 <= b <= 31) or (a == 169 and b == 254))


def _locate(addr: str) -> tuple[float, float, str]:
    """Offline, deterministic geolocation for a target address → (lat, lng, region).

    Honest by design: **internal** RFC1918/loopback hosts have no public geo, so
    they cluster near the ops origin (an internal network, plotted together);
    **external** hosts get a stable hash-derived position. No fabricated city names.
    A real GeoLite2/geoip2 backend can replace this for true public-IP geo later.
    """

    private = _is_private_ip(addr)
    h = int(hashlib.sha256(addr.encode()).hexdigest()[:12], 16)
    if private:
        lat = ATTACKER_ORIGIN[0] + ((h % 1000) / 1000 - 0.5) * 6
        lng = ATTACKER_ORIGIN[1] + ((h // 1000 % 1000) / 1000 - 0.5) * 10
        return round(lat, 4), round(lng, 4), "internal"
    lat = (h % 11000) / 100 - 52          # ~[-52, 58]
    lng = (h // 11000 % 34000) / 100 - 170  # ~[-170, 170]
    return round(lat, 4), round(lng, 4), "external"


# Chain-rung / AD-edge class → ATT&CK technique shown on each hop of a real route.
_KIND_TECH: dict[str, tuple[str, str, str]] = {
    "open-redirect": ("T1190", "Open Redirect", "initial-access"),
    "ssrf": ("T1090", "Server-Side Request Forgery", "discovery"),
    "cloud-metadata": ("T1552.005", "Cloud Instance Metadata", "credential-access"),
    "metadata": ("T1552.005", "Cloud Instance Metadata", "credential-access"),
    "creds": ("T1552", "Unsecured Credentials", "credential-access"),
    "credential-access": ("T1552", "Unsecured Credentials", "credential-access"),
    "credential-dump": ("T1003", "Credential Dumping", "credential-access"),
    "auth-bypass": ("T1078", "Valid Accounts", "privilege-escalation"),
    "foothold": ("T1190", "Foothold — Exploit Public-Facing App", "initial-access"),
    "lfi": ("T1005", "Local File Inclusion / Read", "collection"),
    "source": ("T1083", "Source Disclosure", "discovery"),
    "source-disclosure": ("T1083", "Source Disclosure", "discovery"),
    "sqli": ("T1190", "SQL Injection", "initial-access"),
    "ssti": ("T1059", "Template Injection → RCE", "execution"),
    "cmdi": ("T1059", "OS Command Injection", "execution"),
    "rce": ("T1059", "Remote Code Execution", "execution"),
    "xss": ("T1059.007", "Cross-Site Scripting", "execution"),
    "idor": ("T1190", "Insecure Direct Object Reference", "initial-access"),
}


def _host_of(subject: str) -> str:
    """Host portion of an injection-point URL / ``host:port`` / bare host."""

    from urllib.parse import urlsplit

    subject = (subject or "").strip()
    if "://" in subject:
        return urlsplit(subject).hostname or subject
    return subject.split("/")[0].split("?")[0].split(":")[0]


def _chain_paths(
    chains: list[dict[str, Any]], geo: dict[str, tuple[float, float]]
) -> list[dict[str, Any]]:
    """Turn each engine ``AttackChain`` into a real multi-hop route the console
    renders as a kill chain (entry vuln → escalation rungs → foothold/objective)."""

    default = next(iter(geo.values()), (20.0, 0.0))
    out: list[dict[str, Any]] = []
    for ch in chains:
        rungs = ch.get("steps") or []
        if not rungs:
            continue
        host = _host_of(ch.get("entry") or rungs[0].get("subject", ""))
        slat, slng = geo.get(host, default)
        n = len(rungs)
        steps = []
        for i, s in enumerate(rungs):
            kind = s.get("kind", "")
            tid, tname, phase = _KIND_TECH.get(kind, ("T1190", kind or "step", "initial-access"))
            confirmed = bool(s.get("confirmed"))
            steps.append({
                "role": "entry" if i == 0 else ("crown" if i == n - 1 else "pivot"),
                "label": f"{kind}: {s.get('subject', host)}",
                "layer": "web", "layer_label": _LAYERS["web"]["label"],
                "layer_color": _LAYERS["web"]["color"], "geo": [slat, slng],
                "asset_id": host,
                "technique": {"id": tid, "phase": phase, "framework": "ATT&CK", "name": tname},
                "cve_refs": [], "finding_title": s.get("subject", ""),
                "severity": "crit" if confirmed else "high",
                "exploitability": "confirmed" if confirmed else "reachable",
            })
        depth = int(ch.get("confirmed_depth", 0))
        out.append({
            "id": f"chain-{ch.get('id', len(out))}",
            "severity": "crit" if ch.get("is_realised") else ("high" if depth else "med"),
            "score": round((depth + 1) / (n + 1), 2),
            "layers_traversed": ["web"], "steps": steps,
            "entry_id": host, "crown_id": host,
            "objective": ch.get("objective", ""),
            "is_realised": bool(ch.get("is_realised")),
            "kind": "chain",
        })
    return out


def _ad_paths(
    ad_paths: list[dict[str, Any]], geo: dict[str, tuple[float, float]]
) -> list[dict[str, Any]]:
    """Turn each identity ``ADAttackPath`` into an owned-principal → Domain-Admin route."""

    default = next(iter(geo.values()), (20.0, 0.0))
    out: list[dict[str, Any]] = []
    for i, p in enumerate(ad_paths):
        techs = p.get("techniques") or []
        start, target = p.get("start", "principal"), p.get("target", "Domain Admins")
        lat, lng = default
        hops = [start, *[f"→ {t}" for t in techs], target]
        n = len(hops)
        steps = []
        for j, label in enumerate(hops):
            steps.append({
                "role": "entry" if j == 0 else ("crown" if j == n - 1 else "pivot"),
                "label": label,
                "layer": "identity", "layer_label": _LAYERS["identity"]["label"],
                "layer_color": _LAYERS["identity"]["color"], "geo": [lat, lng],
                "asset_id": start,
                "technique": {"id": techs[j - 1] if 0 < j <= len(techs) else "T1078",
                              "phase": "privilege-escalation", "framework": "ATT&CK",
                              "name": "AD abuse"},
                "cve_refs": [], "finding_title": label,
                "severity": "crit", "exploitability": "confirmed",
            })
        out.append({
            "id": f"ad-{i}", "severity": "crit", "score": 1.0,
            "layers_traversed": ["identity"], "steps": steps,
            "entry_id": start, "crown_id": target,
            "objective": f"Domain compromise: {start} → {target}",
            "is_realised": True, "kind": "identity",
        })
    return out


def build_attack_path(
    assets: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    *,
    chains: list[dict[str, Any]] | None = None,
    ad_paths: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    by_asset = _findings_by_asset(findings)
    points: list[dict[str, Any]] = []
    geo: dict[str, tuple[float, float]] = {}

    entry = pivot = crown = 0
    for a in assets:
        addr = _asset_addr(a)
        fs = by_asset.get(addr, [])
        lat, lng, region = _locate(addr)  # real-ish geo: where the target lives
        geo[addr] = (lat, lng)
        foothold = any(
            f.get("exploitability") == "confirmed" or f.get("severity") in ("crit", "high")
            for f in fs
        )
        # role: confirmed/high foothold → entry; most findings → crown; else pivot
        if foothold or (fs and a.get("exposure") == "external"):
            role, color = "entry", _VOLT
            entry += 1
        elif len(fs) >= 2:
            role, color = "crown", _INCIDENT
            crown += 1
        else:
            role, color = "pivot", _MUTED
            pivot += 1
        r = _asset_risk(fs, a.get("reachable", False))
        layer = _asset_layer(a)
        points.append({
            "id": addr, "label": _asset_label(a), "lat": lat, "lng": lng,
            "color": color, "role": role, "role_color": color,
            "size": 0.4 + min(len(fs), 5) * 0.12,
            "layer": layer, "layer_label": _LAYERS[layer]["label"],
            "exposure": a.get("exposure", "unknown"), "risk": r,
            "geo": {"lat": lat, "lng": lng, "region": region, "ip": addr},
        })

    # ensure at least one crown for a target when we have findings but none marked
    if crown == 0 and points:
        worst = max(points, key=lambda p: p["risk"])
        if worst["role"] != "entry":
            worst["role"], worst["role_color"], worst["color"] = "crown", _INCIDENT, _INCIDENT
            pivot -= 1 if pivot else 0
            crown = 1

    # paths: each confirmed/high finding is a route from its asset toward a crown
    crown_ids = [p["id"] for p in points if p["role"] == "crown"]
    paths: list[dict[str, Any]] = []
    arcs: list[dict[str, Any]] = []
    for f in findings:
        aid = f.get("asset_id")
        if aid not in geo:
            continue
        sev = f.get("severity", "info")
        target = crown_ids[0] if crown_ids else aid
        slat, slng = geo[aid]
        tlat, tlng = geo.get(target, (slat, slng))
        pid = f"path-{f['id']}"
        step_layer = "web"
        steps = [{
            "role": "entry", "label": f.get("title") or f.get("id"),
            "layer": step_layer, "layer_label": _LAYERS[step_layer]["label"],
            "layer_color": _LAYERS[step_layer]["color"], "geo": [slat, slng],
            "asset_id": aid,
            "technique": {"id": f.get("technique_ref") or "T1190",
                          "phase": "initial-access", "framework": "ATT&CK",
                          "name": f.get("title") or "exploit"},
            "cve_refs": f.get("cve_refs") or [], "finding_title": f.get("title"),
            "severity": sev, "exploitability": f.get("exploitability"),
        }]
        paths.append({
            "id": pid, "severity": sev,
            "score": _SEV_RISK.get(sev, 10) / 100,
            "layers_traversed": [step_layer], "steps": steps,
            "entry_id": aid, "crown_id": target,
        })
        if target != aid:
            arcs.append({
                "startLat": slat, "startLng": slng, "endLat": tlat, "endLng": tlng,
                "color": _INCIDENT if sev in ("crit", "high") else _WARN,
                "path_id": pid, "severity": sev, "from_layer": "web", "to_layer": "host",
            })

    # Real chained routes from the engine (WebChainer AttackChains + AD DA paths)
    # lead — a multi-hop kill chain (entry → escalation → foothold/Domain Admin) —
    # with the flat per-finding routes kept after them as supporting detail.
    real_paths = _chain_paths(chains or [], geo) + _ad_paths(ad_paths or [], geo)
    paths = real_paths + paths

    layer_stats = []
    for key, meta in _LAYERS.items():
        members = [p for p in points if p["layer"] == key]
        if not members:
            continue
        layer_stats.append({
            "key": key, "color": meta["color"], "label": meta["label"],
            "count": len(members),
            "sub": f"{sum(1 for p in members if p['role'] == 'entry')} entry",
            "top": max((p["risk"] for p in members), default=0),
        })

    # ambient "incoming breach" arcs from the ops/attacker origin to every target —
    # the cinematic geo layer (real coordinates, not the layer-transition arcs above).
    a_lat, a_lng = ATTACKER_ORIGIN
    geo_arcs = [
        {"startLat": a_lat, "startLng": a_lng, "endLat": p["lat"], "endLng": p["lng"],
         "target": p["id"], "role": p["role"]}
        for p in points
    ]
    # Derive the role tallies + id lists from the FINAL point roles (after the
    # crown-ensure flip) so stats can never disagree with entry_points/crown_jewels
    # (the running counters could drift from the actual roles otherwise).
    entry_ids = [p["id"] for p in points if p["role"] == "entry"]
    pivot_ids = [p["id"] for p in points if p["role"] == "pivot"]
    crown_ids = [p["id"] for p in points if p["role"] == "crown"]
    return {
        "points": points, "arcs": arcs, "paths": paths, "continents": [],
        "layer_stats": layer_stats,
        "attacker_origin": {"lat": a_lat, "lng": a_lng, "label": "OPS ORIGIN"},
        "geo_arcs": geo_arcs,
        "entry_points": entry_ids,
        "crown_jewels": crown_ids,
        "stats": {"entry": len(entry_ids), "pivot": len(pivot_ids),
                  "crown": len(crown_ids), "paths": len(paths), "chains": len(real_paths)},
    }


# ── attack tree (kill-chain hierarchy) ───────────────────────────────────────

#: Ordered kill-chain swimlanes — the depth levels of the intrusion, aligned to
#: the engine's kill chain + MITRE tactics. ``depth`` is the index; the origin
#: root sits in lane 0 and the objective at the bottom.
_TREE_PHASES: tuple[tuple[str, str, str, str], ...] = (
    ("origin", "Operation Origin", "", "Authorized engagement entry"),
    ("recon", "Reconnaissance", "TA0043", "Attack surface mapped"),
    ("initial-access", "Initial Access", "TA0001", "Exploitable entry proven"),
    ("foothold", "Foothold", "TA0002", "Live governed session landed"),
    ("post-ex", "Post-Exploitation", "TA0009", "Loot & captured content"),
    ("escalate", "Privilege Escalation", "TA0004", "Credentials / privileges owned"),
    ("lateral", "Lateral Movement", "TA0008", "Access reused across hosts"),
    ("objective", "Objective", "TA0040", "Crown jewels reached"),
)
_PHASE_COLOR = {
    "origin": _WHITE, "recon": _MUTED, "initial-access": _INFO, "foothold": _VOLT,
    "post-ex": _VOLT, "escalate": _WARN, "lateral": _WARN, "objective": _INCIDENT,
}
_PHASE_INDEX = {p[0]: i for i, p in enumerate(_TREE_PHASES)}
_ORIGIN_ID = "origin"
#: Cap on unconfirmed initial-access candidate nodes shown before they fold into a
#: single "+N more" summary — keeps the tree a readable breach story, not a wall.
_MAX_POTENTIAL_NODES = 10


def _hostkey(addr: str) -> str:
    """Normalise an address for host matching (strip a CIDR/port suffix)."""

    return str(addr or "").split("/", 1)[0].split(":", 1)[0].strip()


def _tree_status(f: dict[str, Any]) -> str:
    """A finding's tree status: confirmed (solid) · reachable · potential (dashed)."""

    if f.get("status") == "confirmed" or f.get("exploitability") == "confirmed":
        return "confirmed"
    if f.get("exploitability") == "reachable" or f.get("reachable"):
        return "reachable"
    return "potential"


def _tree_node(
    node_id: str, phase: str, kind: str, label: str, status: str, *,
    host: str = "", technique: dict[str, Any] | None = None,
    severity: str | None = None, cvss: float | None = None,
    cve_refs: tuple[str, ...] | list[str] = (), detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": node_id, "phase": phase, "depth": _PHASE_INDEX[phase], "kind": kind,
        "label": label, "status": status, "host": host,
        "phase_color": _PHASE_COLOR[phase], "technique": technique,
        "severity": severity, "cvss": cvss, "cve_refs": list(cve_refs),
        "detail": detail or {},
    }


def build_attack_tree(
    assets: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    *,
    chains: list[dict[str, Any]] | None = None,
    ad_paths: list[dict[str, Any]] | None = None,
    sessions: list[dict[str, Any]] | None = None,
    world_model: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the whole attack as a kill-chain tree the console renders.

    Deterministic (no model calls). Nodes are laid out by kill-chain phase
    (:data:`_TREE_PHASES`); ``status`` drives solid (confirmed) vs dashed
    (reachable/potential) rendering. Everything is derived from real engine
    output — reachable assets, CONFIRMED/candidate findings with impact, live C2
    sessions + their proof-of-impact, realised chains, and AD Domain-Admin paths —
    so the tree is the true breach story, never a mock.
    """

    sessions = sessions or []
    ad_paths = ad_paths or []
    world_model = world_model or {}
    nodes: list[dict[str, Any]] = [
        _tree_node(_ORIGIN_ID, "origin", "origin", "OPS ORIGIN", "confirmed",
                   detail={"note": "Authorized operation entry point."})
    ]
    edges: list[dict[str, Any]] = []

    def add_edge(source: str, target: str, status: str) -> None:
        edges.append({"source": source, "target": target, "status": status})

    # phase presence per host, so we can wire a top-down lineage per host
    host_phase: dict[str, dict[str, list[str]]] = {}

    def register(node: dict[str, Any]) -> None:
        nodes.append(node)
        host_phase.setdefault(_hostkey(node["host"]), {}).setdefault(
            node["phase"], []).append(node["id"])

    # 1) Recon — every reachable asset (or one carrying findings) is a mapped host.
    by_asset = _findings_by_asset(findings)
    for a in assets:
        addr = _asset_addr(a)
        hk = _hostkey(addr)
        if not hk:
            continue
        fs = by_asset.get(addr, [])
        if not a.get("reachable") and not fs:
            continue
        register(_tree_node(
            f"asset-{hk}", "recon", "asset", _asset_label(a),
            "confirmed" if a.get("reachable") else "potential", host=addr,
            detail={"exposure": a.get("exposure"), "type": a.get("type"),
                    "open_findings": len(fs)},
        ))

    # 2) Initial access — real vulnerability findings (exposed-service rows are the
    #    recon layer, so skip them here; their correlated CVEs still land as findings).
    #    Keep the tree readable: render every CONFIRMED entry, plus the strongest
    #    unconfirmed candidates up to a cap; the rest fold into one honest "+N more"
    #    node (rule #8 — no silent truncation).
    ia_findings = [f for f in findings
                   if not str(f.get("type") or "").lower().startswith("exposed-service")]
    confirmed_f = [f for f in ia_findings if _tree_status(f) == "confirmed"]
    other_f = sorted(
        (f for f in ia_findings if _tree_status(f) != "confirmed"),
        key=lambda f: (_SEV_ORDER.get(f.get("severity", "info"), 9), -(f.get("cvss") or 0)),
    )
    shown_other = other_f[:_MAX_POTENTIAL_NODES]
    for f in confirmed_f + shown_other:
        ftype = str(f.get("type") or "").lower()
        host = f.get("asset_id") or ""
        register(_tree_node(
            f"find-{f.get('id')}", "initial-access", "finding",
            f.get("title") or f.get("id") or "finding", _tree_status(f), host=host,
            technique={"id": f.get("technique_ref") or "T1190",
                       "name": f.get("title") or ftype},
            severity=f.get("severity"), cvss=f.get("cvss"),
            cve_refs=f.get("cve_refs") or [],
            detail={"remediation": f.get("remediation"),
                    "reachability_reason": f.get("reachability_reason"),
                    "exploitability": f.get("exploitability"),
                    "status": f.get("status"), "type": ftype},
        ))
    hidden = len(other_f) - len(shown_other)
    if hidden > 0:
        register(_tree_node(
            "find-more", "initial-access", "finding",
            f"+{hidden} more reachable candidates", "potential",
            detail={"note": "Additional lower-confidence injection candidates from "
                            "the crawl — inspect the Findings tab for the full list."},
        ))

    # 3) Foothold — every live C2 session, with its proof-of-impact as a post-ex child.
    for s in sessions:
        sid = s.get("id")
        host = s.get("host") or ""
        proof = s.get("proof") or {}
        whoami = proof.get("whoami") or "shell"
        status = "confirmed" if s.get("status") != "closed" else "reachable"
        register(_tree_node(
            f"sess-{sid}", "foothold", "session", f"{whoami}@{_hostkey(host)}", status,
            host=host, technique={"id": s.get("technique") or "T1190", "name": "Foothold"},
            severity="crit", detail={"proof": proof, "session_id": sid,
                                     "kind": s.get("kind"), "opened_at": s.get("opened_at")},
        ))
        loot = s.get("loot") or []
        site = s.get("site_content")
        if loot or site:
            register(_tree_node(
                f"loot-{sid}", "post-ex", "loot", "Loot & captured content", "confirmed",
                host=host, detail={"loot": loot, "site_content": site},
            ))
            add_edge(f"sess-{sid}", f"loot-{sid}", "confirmed")

    # 4) Escalation / lateral / objective — owned principals + AD Domain-Admin paths.
    owned = world_model.get("owned_principals") or world_model.get("owned") or []
    for i, principal in enumerate(owned):
        register(_tree_node(
            f"own-{i}", "escalate", "credential", str(principal), "confirmed",
            technique={"id": "T1078", "name": "Valid Accounts"},
            detail={"principal": principal},
        ))
    objective_ids: list[str] = []
    for i, p in enumerate(ad_paths):
        target = p.get("target", "Domain Admins")
        oid = f"objective-ad-{i}"
        register(_tree_node(
            oid, "objective", "ad", f"Domain Admin — {target}", "confirmed",
            technique={"id": "T1078", "name": "Domain Admin"},
            severity="crit", detail={"start": p.get("start"), "target": target,
                                     "techniques": p.get("techniques") or []},
        ))
        objective_ids.append(oid)
    # A realised web/host chain that reaches a foothold is itself an objective when no
    # AD path exists (the engagement's crown was a proven host compromise).
    realised = [c for c in (chains or []) if c.get("is_realised")]
    if not objective_ids and realised:
        oid = "objective-chain"
        register(_tree_node(
            oid, "objective", "objective", "Objective reached — host compromised",
            "confirmed", severity="crit",
            detail={"chains": [c.get("objective") or c.get("id") for c in realised]},
        ))
        objective_ids.append(oid)

    # ── wire the lineage: origin → recon → initial-access → foothold → post-ex,
    #    per host, then the deepest host frontier → escalation/objective ──────────
    _PHASE_FLOW = ["recon", "initial-access", "foothold", "post-ex"]
    frontier: list[tuple[str, str]] = []  # (node_id, status) — deepest node per host
    for _hk, phases in host_phase.items():
        present = [ph for ph in _PHASE_FLOW if phases.get(ph)]
        # origin → the shallowest present node(s) for this host
        if present:
            for nid in phases[present[0]]:
                st = _node_status_by_id(nodes, nid)
                add_edge(_ORIGIN_ID, nid, st)
        # chain consecutive present phases (all parents → all children)
        for a_ph, b_ph in pairwise(present):
            for src in phases[a_ph]:
                for dst in phases[b_ph]:
                    add_edge(src, dst, _node_status_by_id(nodes, dst))
        if present:
            for nid in phases[present[-1]]:
                frontier.append((nid, _node_status_by_id(nodes, nid)))

    # escalation/objective: hang the AD/objective nodes off the deepest frontier
    # (or origin if we never landed a foothold), so the tree always reaches its top.
    esc_ids = [n["id"] for n in nodes if n["phase"] == "escalate"]
    parents = [nid for nid, _ in frontier] or [_ORIGIN_ID]
    for eid_ in esc_ids:
        for parent in parents:
            add_edge(parent, eid_, "confirmed")
    obj_parents = esc_ids or [nid for nid, _ in frontier] or [_ORIGIN_ID]
    for oid in objective_ids:
        for parent in obj_parents:
            add_edge(parent, oid, "confirmed")

    # any node still without an incoming edge → attach to origin (never orphan)
    has_parent = {e["target"] for e in edges}
    for n in nodes:
        if n["id"] != _ORIGIN_ID and n["id"] not in has_parent:
            add_edge(_ORIGIN_ID, n["id"], n["status"])

    # dedupe edges (a node can be wired by both the explicit post-ex link and the
    # per-host phase flow); keep first occurrence / its status.
    seen_edges: set[tuple[str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for e in edges:
        key = (e["source"], e["target"])
        if key in seen_edges:
            continue
        seen_edges.add(key)
        deduped.append(e)
    edges = deduped

    ia_nodes = [n for n in nodes if n["phase"] == "initial-access"]
    summary = {
        "entry_points": len(ia_nodes),
        "confirmed_findings": sum(1 for n in ia_nodes if n["status"] == "confirmed"),
        "live_footholds": sum(1 for n in nodes
                              if n["kind"] == "session" and n["status"] == "confirmed"),
        "crown_reached": len(objective_ids),
        "domain_admin": bool(ad_paths),
    }
    phase_defs = [{"key": k, "label": lbl, "tactic": t, "hint": h,
                   "color": _PHASE_COLOR[k]} for k, lbl, t, h in _TREE_PHASES]
    return {"phases": phase_defs, "nodes": nodes, "edges": edges, "summary": summary}


def _node_status_by_id(nodes: list[dict[str, Any]], node_id: str) -> str:
    for n in nodes:
        if n["id"] == node_id:
            return str(n["status"])
    return "potential"


# ── report summary ────────────────────────────────────────────────────────────

def build_report_summary(
    findings: list[dict[str, Any]], asset_count: int, audit_count: int, audit_valid: bool
) -> dict[str, Any]:
    open_by_sev: dict[str, int] = {}
    closed = 0
    for f in findings:
        if f.get("status") in ("closed", "false-positive"):
            closed += 1
        else:
            sev = f.get("severity", "info")
            open_by_sev[sev] = open_by_sev.get(sev, 0) + 1
    return {
        "assets": asset_count,
        "findings_total": len(findings),
        "findings_open_by_severity": open_by_sev,
        "findings_closed": closed,
        "agent_runs": 0,
        "audit_events": audit_count,
        "audit_chain_valid": audit_valid,
    }
