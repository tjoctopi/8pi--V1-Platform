"""Presentation builders — engine data → the console's richer view payloads.

The threat-map (force graph) and attack-path (globe) tabs need shapes the engine
doesn't produce directly: layer classification, per-asset risk, and — for the
globe — a geographic-ish projection. Those are *presentation* concerns, so they
live here rather than in the engine. Everything is derived deterministically
from the already-translated console asset/finding dicts (see
:mod:`attack_engine.api.serialize`), so the same real scan drives every view.
"""

from __future__ import annotations

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


def build_attack_path(
    assets: list[dict[str, Any]], findings: list[dict[str, Any]]
) -> dict[str, Any]:
    by_asset = _findings_by_asset(findings)
    points: list[dict[str, Any]] = []
    geo: dict[str, tuple[float, float]] = {}
    total = len(assets)

    entry = pivot = crown = 0
    for i, a in enumerate(assets):
        addr = _asset_addr(a)
        fs = by_asset.get(addr, [])
        lat, lng = _geo_for(i, total)
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

    return {
        "points": points, "arcs": arcs, "paths": paths, "continents": [],
        "layer_stats": layer_stats,
        "entry_points": [p["id"] for p in points if p["role"] == "entry"],
        "crown_jewels": crown_ids,
        "stats": {"entry": entry, "pivot": max(pivot, 0), "crown": crown,
                  "paths": len(paths)},
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
