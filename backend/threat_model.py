"""C-08 Threat-Model Engine. Living risk map over the asset graph (IF-GRAPH).
Enriched with ecosystem-layer classification, product/version fingerprints, exposed
ports, top finding + CVE list, and exposure — so the interactive threat map can show
rich telemetry on hover / click."""
from fastapi import APIRouter
from db import db
from attack_path import _classify_layer, LAYERS

router = APIRouter()

_SEV_SCORE = {"crit": 100, "high": 80, "med": 50, "low": 25, "info": 5}
_EXPLOIT_MULT = {"confirmed": 1.4, "reachable": 1.2, "unconfirmed": 1.0}


def _label(a):
    i = a.get("identifiers") or {}
    base = i.get("url") or i.get("host") or i.get("ip") or a["_id"][:8]
    if a.get("type") == "service" and i.get("port"):
        return f"{base}:{i.get('port')}"
    return base


async def build_map(engagement_id):
    assets = await db.assets.find({"engagement_id": engagement_id}).to_list(2000)
    findings = await db.findings.find({"engagement_id": engagement_id}).to_list(5000)

    open_findings_by_asset = {}
    top_finding_by_asset = {}
    risk_by_asset = {}
    for f in findings:
        if f.get("status") in ("closed", "false-positive"):
            continue
        base = _SEV_SCORE.get(f.get("severity", "info"), 5)
        mult = _EXPLOIT_MULT.get(f.get("exploitability", "unconfirmed"), 1.0)
        score = base * mult
        aid = f.get("asset_id")
        risk_by_asset[aid] = risk_by_asset.get(aid, 0) + score
        open_findings_by_asset[aid] = open_findings_by_asset.get(aid, 0) + 1
        prev = top_finding_by_asset.get(aid)
        if not prev or _SEV_SCORE.get(f.get("severity", "info"), 5) > _SEV_SCORE.get(prev.get("severity", "info"), 5):
            top_finding_by_asset[aid] = f

    nodes, edges, risk = [], [], []
    for a in assets:
        exposure = a.get("exposure", "unknown")
        score = round(risk_by_asset.get(a["_id"], 0), 1)
        # exposure weighting: external + exploitable ranks higher than raw CVSS (FR-TM-02)
        weighted = round(score * (1.5 if exposure == "external" else 1.0), 1)
        layer = _classify_layer(a)
        layer_meta = LAYERS[layer]
        versions = a.get("versions") or []
        top_prod = versions[0] if versions else {}
        idents = a.get("identifiers") or {}
        top = top_finding_by_asset.get(a["_id"])
        nodes.append({
            "id": a["_id"], "type": a.get("type"),
            "label": _label(a),
            "exposure": exposure,
            "risk": weighted,
            "raw_risk": score,
            "parent": a.get("attributes", {}).get("parent"),
            "layer": layer,
            "layer_label": layer_meta["label"],
            "layer_color": layer_meta["color"],
            "product": top_prod.get("product") if top_prod else None,
            "version": top_prod.get("version") if top_prod else None,
            "port": idents.get("port"),
            "host": idents.get("host") or idents.get("ip"),
            "url": idents.get("url"),
            "last_seen": a.get("last_seen"),
            "open_findings": open_findings_by_asset.get(a["_id"], 0),
            "top_finding": ({
                "id": top["_id"], "title": top.get("title"),
                "severity": top.get("severity"),
                "exploitability": top.get("exploitability"),
                "cve_refs": top.get("cve_refs", []),
                "kev": top.get("kev", False),
            } if top else None),
        })
        if weighted > 0:
            risk.append({"asset_id": a["_id"], "score": weighted})
    for a in assets:
        parent = a.get("attributes", {}).get("parent")
        if parent:
            edges.append({"source": parent, "target": a["_id"], "relation": "runs"})

    risk.sort(key=lambda r: r["score"], reverse=True)
    # summary per-layer for the threat-map legend
    layer_summary = {}
    for n in nodes:
        l = n["layer"]
        s = layer_summary.setdefault(l, {"key": l, "label": n["layer_label"], "color": n["layer_color"],
                                          "count": 0, "risk": 0, "external": 0, "findings": 0})
        s["count"] += 1
        s["risk"] += n["risk"]
        s["findings"] += n["open_findings"]
        if n["exposure"] == "external":
            s["external"] += 1
    for s in layer_summary.values():
        s["risk"] = round(s["risk"], 1)
    return {"nodes": nodes, "edges": edges, "risk": risk, "layers": list(layer_summary.values())}


async def candidate_targets(engagement_id):
    """In-scope candidate assets for the offensive agent, ranked by weighted risk (FR-TM-04)."""
    m = await build_map(engagement_id)
    ranked = sorted(m["nodes"], key=lambda n: n["risk"], reverse=True)
    return ranked


@router.get("/engagements/{eid}/threat-map")
async def get_threat_map(eid: str):
    return await build_map(eid)
