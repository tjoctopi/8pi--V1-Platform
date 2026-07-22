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
    return {
        "points": points, "arcs": arcs, "paths": paths, "continents": [],
        "layer_stats": layer_stats,
        "attacker_origin": {"lat": a_lat, "lng": a_lng, "label": "OPS ORIGIN"},
        "geo_arcs": geo_arcs,
        "entry_points": [p["id"] for p in points if p["role"] == "entry"],
        "crown_jewels": crown_ids,
        "stats": {"entry": entry, "pivot": max(pivot, 0), "crown": crown,
                  "paths": len(paths), "chains": len(real_paths)},
    }


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
