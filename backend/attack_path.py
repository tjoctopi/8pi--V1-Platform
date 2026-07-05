"""Attack-path engine: classifies every asset into an ECOSYSTEM LAYER
(code, dev, onprem, cloud, saas, endpoint, edge/IoT/AI) and pins it to a
stylised continent on the 8pi ecosystem globe. Derives entry-point → pivot
→ crown-jewel paths that traverse layers, and streams a real-time (SSE)
AI attack-path narrative through the Model Gateway (BYOM)."""
import os
import json
import uuid
import asyncio
import hashlib
import time
from collections import defaultdict
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from db import db
from store import doc_out, get_engagement
from audit import audit_event
from bedrock import BEDROCK_MODEL_ID, converse_stream

router = APIRouter()

DATASTORE_PRODUCTS = {"mysql", "samba", "vsftpd", "proftpd", "postgresql", "mongodb", "redis", "mssql"}
DATASTORE_PORTS = {3306, 445, 21, 5432, 27017, 6379, 1433}
WEB_PORTS = {80, 443, 8080, 8443}
SEV_W = {"crit": 100, "high": 70, "med": 40, "low": 20, "info": 5}
ROLE_COLOR = {"entry": "#FFFFFF", "pivot": "#7A7A7A", "crown": "#FF00A0"}

TECH = {
    "entry": {"id": "T1190", "name": "Exploit Public-Facing Application", "framework": "MITRE ATT&CK", "phase": "Initial Access"},
    "pivot": {"id": "T1021", "name": "Remote Services (lateral movement)", "framework": "MITRE ATT&CK", "phase": "Lateral Movement"},
    "crown": {"id": "T1005", "name": "Data from Local System (objective)", "framework": "MITRE ATT&CK", "phase": "Collection / Impact"},
}

# ────────────────────────── ECOSYSTEM LAYERS (B/W cyberpunk) ──────────────────────────
# Each layer is a stylised "continent" on the 8π globe. Grayscale wayfinding — the
# ONE hue (hot magenta) is reserved for the crown-jewel layers so the eye follows
# the breach into it. Coords are lng/lat because GeoJSON stores as [lng, lat].
LAYERS = {
    "endpoint": {
        "label": "Endpoints",
        "sub": "User devices · admin surface",
        "color": "#B4EE00",     # electric lime
        "center": [55, -135],
        "polygon": [[-170, 42], [-165, 62], [-140, 72], [-108, 68], [-92, 55], [-100, 42], [-135, 34], [-165, 36], [-170, 42]],
    },
    "saas": {
        "label": "SaaS",
        "sub": "Third-party apps · identity",
        "color": "#9D4EDD",     # violet
        "center": [48, 90],
        "polygon": [[35, 38], [30, 58], [55, 70], [95, 70], [130, 60], [148, 44], [130, 30], [90, 26], [50, 30], [35, 38]],
    },
    "edge": {
        "label": "Edge / IoT / AI",
        "sub": "Inference nodes · devices",
        "color": "#FF6D9C",     # soft pink
        "center": [5, 132],
        "polygon": [[92, -12], [88, 12], [110, 24], [140, 22], [168, 14], [172, -4], [155, -14], [125, -18], [92, -12]],
    },
    "cloud": {
        "label": "Cloud",
        "sub": "IaaS · PaaS · public infra",
        "color": "#4D9CFF",     # sky blue
        "center": [8, 15],
        "polygon": [[-32, -16], [-38, 12], [-20, 26], [12, 30], [42, 24], [58, 10], [50, -8], [28, -20], [-2, -22], [-32, -16]],
    },
    "dev": {
        "label": "Dev / CI-CD",
        "sub": "Pipelines · runners · staging",
        "color": "#FF8B1A",     # orange
        "center": [-2, -75],
        "polygon": [[-115, -18], [-112, 10], [-92, 22], [-68, 22], [-48, 12], [-42, -4], [-52, -18], [-88, -22], [-115, -18]],
    },
    "onprem": {
        "label": "On-Prem",
        "sub": "Datacenter · legacy · DBs",
        "color": "#0EEBC7",     # teal
        "center": [-42, -60],
        "polygon": [[-102, -60], [-108, -42], [-96, -26], [-70, -22], [-38, -28], [-28, -46], [-42, -62], [-80, -66], [-102, -60]],
    },
    "code": {
        "label": "Code",
        "sub": "Source · artifacts · secrets",
        "color": "#FFF71A",     # bright yellow
        "center": [-42, 62],
        "polygon": [[20, -58], [16, -32], [30, -20], [58, -18], [88, -22], [102, -36], [96, -52], [70, -62], [42, -62], [20, -58]],
    },
}

# order matters for legend + fallback role→layer mapping
LAYER_ORDER = ["endpoint", "saas", "cloud", "dev", "code", "onprem", "edge"]


def _h(s, mod):
    return int(hashlib.sha256(str(s).encode()).hexdigest(), 16) % mod


def _label(a):
    i = a.get("identifiers", {})
    base = i.get("url") or i.get("host") or i.get("ip") or a["_id"][:8]
    if a.get("type") == "service" and i.get("port"):
        return f"{base}:{i.get('port')}"
    return base


def _asset_products(a):
    versions = a.get("versions") or []
    idents = a.get("identifiers") or {}
    tokens = [(v.get("product") or "").lower() for v in versions]
    for k in ("host", "url", "ip", "service"):
        val = idents.get(k)
        if val:
            tokens.append(str(val).lower())
    for t in a.get("tags") or []:
        tokens.append(str(t).lower())
    return " ".join(tokens)


def _classify_layer(a):
    """Map an asset to one of the 7 ecosystem layers by product + identity hints."""
    prod = _asset_products(a)
    ident = a.get("identifiers") or {}
    port = ident.get("port")
    tags = [str(t).lower() for t in (a.get("tags") or [])]
    exposure = a.get("exposure", "internal")
    t = a.get("type", "host")

    if any(s in prod for s in ("salesforce", "okta", "workday", "hubspot", "notion", "atlassian",
                                "jira", "confluence", "slack.com", "zendesk", "servicenow",
                                "sharepoint", "office365", "onedrive", "google workspace", "gmail")) or "saas" in tags:
        return "saas"
    if any(s in prod for s in ("gitlab", "gitea", "github", "bitbucket", "artifactory",
                                "nexus", "harbor", "gerrit")) or "repo" in tags or "code" in tags:
        return "code"
    if any(s in prod for s in ("jenkins", "argocd", "argo-cd", "gitlab-runner", "tekton",
                                "sonarqube", "kubernetes", "kubelet", "helm", "spinnaker",
                                "buildkite", "circleci", "teamcity")) or any(k in prod for k in ("-dev", "-staging", "-ci")) or "ci" in tags or "cicd" in tags:
        return "dev"
    if any(s in prod for s in ("aws", "amazonaws", "azurewebsites", "windows.net", "gcp",
                                "googleapis", "cloudfront", "cloudflare", ".s3", "ec2",
                                "digitalocean", "linode", "heroku", "vercel", "netlify")) or "cloud" in tags:
        return "cloud"
    if any(s in prod for s in ("mikrotik", "ubiquiti", "unifi", "iot", "camera", "coral",
                                "jetson", "tinyml", "edge-", "modbus", "profinet", "opcua",
                                "zigbee", "lorawan", "sigfox")) or any(x in tags for x in ("iot", "edge", "ot", "ics")):
        return "edge"
    if any(s in prod for s in ("windows 10", "windows 11", "macos", "mac os", "chromebook",
                                "workstation", "laptop", "-lap", "-wks", "-desktop")) or any(x in tags for x in ("endpoint", "workstation", "byod")):
        return "endpoint"
    # web-facing tiers → cloud when externally exposed, else on-prem
    if exposure == "external" and (t == "webapp" or port in WEB_PORTS or any(s in prod for s in ("nginx", "apache", "httpd", "tomcat"))):
        return "cloud"
    # datastore → onprem
    if any(s in prod for s in DATASTORE_PRODUCTS) or port in DATASTORE_PORTS:
        return "onprem"
    # SSH admin surface → endpoint (admin)
    if "openssh" in prod or port == 22:
        return "endpoint"
    # tomcat/jenkins-style internal web tiers → dev (staging middleware)
    if any(s in prod for s in ("tomcat", "jetty", "weblogic")):
        return "dev"
    # nginx/apache internal reverse proxies → cloud (as the client's "web tier")
    if any(s in prod for s in ("nginx", "apache", "httpd")):
        return "cloud"
    return "onprem"


def _geo_layer(aid, layer):
    """Deterministic jitter inside the layer's continent bounding area."""
    c = LAYERS[layer]["center"]  # lat, lng
    dy = (_h(aid, 240) - 120) / 22.0
    dx = (_h(aid + "x", 480) - 240) / 16.0
    return [c[0] + dy, c[1] + dx]


def _classify_role(a, findings_by_asset):
    t = a.get("type")
    ident = a.get("identifiers", {})
    versions = a.get("versions") or []
    prod = (versions[0].get("product", "").lower() if versions else "")
    port = ident.get("port")
    if t == "service":
        if any(d in prod for d in DATASTORE_PRODUCTS) or (port in DATASTORE_PORTS):
            return "crown"
        if port in WEB_PORTS:
            return "entry"
        return "pivot"
    if t == "webapp":
        return "entry"
    fs = findings_by_asset.get(a["_id"], [])
    if a.get("exposure") == "external" or any(f.get("exploitability") in ("reachable", "confirmed") for f in fs):
        return "entry"
    return "pivot"


def _top_finding(aid, findings_by_asset, reachable_only=False):
    fs = findings_by_asset.get(aid, [])
    if reachable_only:
        fs = [f for f in fs if f.get("exploitability") in ("reachable", "confirmed")]
    fs = sorted(fs, key=lambda f: (f.get("exploitability") == "confirmed", f.get("cvss", 0)), reverse=True)
    return fs[0] if fs else None


def _step(a, role, layer, findings_by_asset):
    f = _top_finding(a["_id"], findings_by_asset, reachable_only=(role != "pivot")) or _top_finding(a["_id"], findings_by_asset)
    return {
        "asset_id": a["_id"], "label": _label(a), "type": a.get("type"), "role": role,
        "layer": layer, "layer_label": LAYERS[layer]["label"], "layer_color": LAYERS[layer]["color"],
        "exposure": a.get("exposure"), "technique": TECH[role], "geo": _geo_layer(a["_id"], layer),
        "finding_id": f["_id"] if f else None,
        "finding_title": f["title"] if f else None,
        "severity": f["severity"] if f else "info",
        "exploitability": f.get("exploitability") if f else "unconfirmed",
        "cve_refs": f.get("cve_refs", []) if f else [],
    }


async def compute(engagement_id):
    assets = await db.assets.find({"engagement_id": engagement_id}).to_list(3000)
    findings = await db.findings.find({"engagement_id": engagement_id, "status": {"$nin": ["closed", "false-positive"]}}).to_list(5000)
    by_asset = defaultdict(list)
    for f in findings:
        if f.get("asset_id"):
            by_asset[f["asset_id"]].append(f)
    by_id = {a["_id"]: a for a in assets}

    layers = {a["_id"]: _classify_layer(a) for a in assets}
    roles = {a["_id"]: _classify_role(a, by_asset) for a in assets}

    risk = {}
    for aid, fs in by_asset.items():
        risk[aid] = sum(
            SEV_W.get(f.get("severity", "info"), 5)
            * (1.4 if f.get("exploitability") == "confirmed"
               else 1.2 if f.get("exploitability") == "reachable"
               else 1.0)
            for f in fs
        )

    entries = [a for a in assets if roles[a["_id"]] == "entry"]
    crowns = [a for a in assets if roles[a["_id"]] == "crown"]

    def _entry_key(a):
        return (
            a.get("type") == "webapp",
            layers[a["_id"]] in ("saas", "endpoint", "edge", "cloud"),
            any(f.get("exploitability") in ("reachable", "confirmed") for f in by_asset.get(a["_id"], [])),
            risk.get(a["_id"], 0),
        )
    entries_ranked = sorted(entries, key=_entry_key, reverse=True)

    paths = []
    for crown in sorted(crowns, key=lambda a: risk.get(a["_id"], 0), reverse=True)[:6]:
        parent = by_id.get((crown.get("attributes") or {}).get("parent"))
        parent_id = parent["_id"] if parent else None
        entry = next((e for e in entries_ranked if e["_id"] not in (crown["_id"], parent_id)), None)
        if not entry:
            entry = parent if (parent and roles.get(parent_id) == "entry") else (entries_ranked[0] if entries_ranked else parent)
        if not entry:
            continue
        steps = [_step(entry, "entry", layers[entry["_id"]], by_asset)]
        if parent and parent_id not in (entry["_id"], crown["_id"]):
            steps.append(_step(parent, "pivot", layers[parent_id], by_asset))
        steps.append(_step(crown, "crown", layers[crown["_id"]], by_asset))
        score = sum(SEV_W.get(s["severity"], 5) for s in steps)
        max_sev = max(steps, key=lambda s: SEV_W.get(s["severity"], 5))["severity"]
        paths.append({"id": uuid.uuid4().hex[:8], "steps": steps, "score": score, "severity": max_sev,
                      "entry_id": entry["_id"], "crown_id": crown["_id"],
                      "layers_traversed": [s["layer"] for s in steps]})
    paths.sort(key=lambda p: p["score"], reverse=True)
    paths = paths[:4]

    # globe points (all assets) — coloured by LAYER, sized by risk
    points = []
    for a in assets:
        lyr = layers[a["_id"]]
        rol = roles[a["_id"]]
        g = _geo_layer(a["_id"], lyr)
        r = risk.get(a["_id"], 0)
        points.append({
            "id": a["_id"], "label": _label(a), "lat": g[0], "lng": g[1],
            "role": rol, "layer": lyr, "layer_label": LAYERS[lyr]["label"],
            "exposure": a.get("exposure"), "risk": round(r, 1),
            "color": LAYERS[lyr]["color"],
            "role_color": ROLE_COLOR[rol],
            "size": min(0.35, 0.08 + r / 800.0),
        })

    # arcs from path segments
    arcs = []
    for p in paths:
        for i in range(len(p["steps"]) - 1):
            s, t = p["steps"][i], p["steps"][i + 1]
            arcs.append({
                "startLat": s["geo"][0], "startLng": s["geo"][1],
                "endLat": t["geo"][0], "endLng": t["geo"][1],
                "color": [LAYERS[s["layer"]]["color"], LAYERS[t["layer"]]["color"]],
                "path_id": p["id"], "severity": p["severity"],
                "from_layer": s["layer"], "to_layer": t["layer"],
            })

    # per-layer stats (count + risk + top asset)
    layer_stats = []
    for key in LAYER_ORDER:
        assets_in = [a for a in assets if layers[a["_id"]] == key]
        r_sum = sum(risk.get(a["_id"], 0) for a in assets_in)
        top = max(assets_in, key=lambda a: risk.get(a["_id"], 0), default=None)
        layer_stats.append({
            "key": key,
            "label": LAYERS[key]["label"],
            "sub": LAYERS[key]["sub"],
            "color": LAYERS[key]["color"],
            "count": len(assets_in),
            "risk": round(r_sum, 1),
            "top": _label(top) if top else None,
        })

    # continents payload (GeoJSON features) so the frontend can draw them without hard-coding
    continents = []
    for key in LAYER_ORDER:
        L = LAYERS[key]
        continents.append({
            "key": key,
            "label": L["label"],
            "sub": L["sub"],
            "color": L["color"],
            "center": {"lat": L["center"][0], "lng": L["center"][1]},
            "geometry": {"type": "Polygon", "coordinates": [L["polygon"]]},
        })

    brief = lambda a: {
        "id": a["_id"], "label": _label(a), "type": a.get("type"),
        "exposure": a.get("exposure"), "layer": layers[a["_id"]],
        "layer_label": LAYERS[layers[a["_id"]]]["label"],
    }
    return {
        "paths": paths,
        "points": points,
        "arcs": arcs,
        "entry_points": [brief(a) for a in entries],
        "crown_jewels": [brief(a) for a in crowns],
        "continents": continents,
        "layer_stats": layer_stats,
        "stats": {
            "entry": len(entries), "crown": len(crowns),
            "pivot": sum(1 for r in roles.values() if r == "pivot"),
            "paths": len(paths),
        },
    }


@router.get("/engagements/{eid}/attack-path")
async def attack_path(eid: str):
    eng = await get_engagement(eid)
    if not eng:
        raise HTTPException(status_code=404, detail="engagement not found")
    return await compute(eid)


def _build_prompt(data):
    lines = ["Discovered attack surface for an authorized purple-team engagement.",
             f"Entry points: {data['stats']['entry']}, crown jewels: {data['stats']['crown']}.",
             f"Ecosystem layers observed: " + ", ".join(f"{s['label']}({s['count']})" for s in data['layer_stats'] if s['count']),
             ""]
    for i, p in enumerate(data["paths"][:3], 1):
        lines.append(f"Candidate path {i} (severity {p['severity']}), traversing "
                     f"{ ' → '.join(p['layers_traversed']) }:")
        for s in p["steps"]:
            cve = ", ".join(s.get("cve_refs") or []) or "n/a"
            lines.append(f"  - {s['role'].upper()} [{s['layer_label']}] {s['label']} ({s['exposure']}) "
                         f"{s['technique']['id']} {s['technique']['name']} "
                         f"| finding: {s.get('finding_title') or 'none'} "
                         f"({s.get('exploitability')}, {cve})")
        lines.append("")
    return "\n".join(lines)


def _fallback(data):
    if not data["paths"]:
        return "No exploitable path to crown-jewel assets was found with the current findings. Expand sensing or raise RoE intensity to enumerate deeper."
    p = data["paths"][0]
    out = [f"MOST LIKELY ATTACK PATH (severity {p['severity'].upper()}) — traversing {' → '.join(p['layers_traversed'])}:\n"]
    for i, s in enumerate(p["steps"], 1):
        cve = ", ".join(s.get("cve_refs") or []) or "no CVE"
        out.append(f"{i}. [{s['layer_label']}] {s['technique']['phase']} — {s['technique']['id']} against {s['label']} "
                   f"({s['exposure']}). Leverages {s.get('finding_title') or 'observed exposure'} [{cve}], "
                   f"reachable because it is {s.get('exploitability')}.")
    out.append("\nImpact: an external foothold chains laterally into the crown-jewel datastore, enabling data collection/exfiltration. "
               "Prioritise patching the entry-point CVE and segmenting the datastore.")
    return "\n".join(out)


@router.get("/engagements/{eid}/attack-path/stream")
async def attack_path_stream(eid: str):
    eng = await get_engagement(eid)
    if not eng:
        raise HTTPException(status_code=404, detail="engagement not found")
    data = await compute(eid)
    prompt = _build_prompt(data)

    system_msg = ("You are 8pi's offensive analyst. Given the discovered assets grouped by ECOSYSTEM LAYER "
                  "(Endpoints, SaaS, Cloud, Dev/CI-CD, Code, On-Prem, Edge/IoT/AI) and candidate paths, "
                  "narrate the single most likely real-world attack path from an external entry point to "
                  "the crown-jewel assets. Explicitly call out each layer transition (e.g. 'Endpoints → "
                  "Cloud → On-Prem'). Reference specific CVEs/findings and MITRE ATT&CK techniques. "
                  "5-7 tight steps, punchy operator tone. End with the priority fix per layer.")

    async def gen():
        yield f'data: {json.dumps({"status": "start", "paths": len(data["paths"])})}\n\n'
        started = time.time()
        acc = ""
        route = "hosted-frontier"
        try:
            loop = asyncio.get_event_loop()
            queue: asyncio.Queue = asyncio.Queue()

            def produce():
                # Blocking Bedrock ConverseStream iteration on a worker thread;
                # deltas are pushed back to the event loop via the queue.
                try:
                    resp = converse_stream(system_msg, prompt, 1200)
                    for event in resp["stream"]:
                        if "contentBlockDelta" in event:
                            piece = event["contentBlockDelta"]["delta"].get("text")
                            if piece:
                                loop.call_soon_threadsafe(queue.put_nowait, ("delta", piece))
                        elif "messageStop" in event:
                            break
                    loop.call_soon_threadsafe(queue.put_nowait, ("done", None))
                except Exception as exc:  # noqa: BLE001
                    loop.call_soon_threadsafe(queue.put_nowait, ("error", str(exc)[:120]))

            asyncio.create_task(asyncio.to_thread(produce))
            while True:
                kind, val = await queue.get()
                if kind == "done":
                    break
                if kind == "error":
                    raise RuntimeError(val)
                acc += val
                yield f'data: {json.dumps({"delta": val})}\n\n'
        except (asyncio.CancelledError, GeneratorExit):
            return
        except Exception as e:
            route = "local-openweight"
            for word in (_fallback(data) + f"\n\n(hosted route unavailable: {str(e)[:80]})").split(" "):
                acc += word + " "
                yield f'data: {json.dumps({"delta": word + " "})}\n\n'
                await asyncio.sleep(0.015)
        latency = int((time.time() - started) * 1000)
        usage = {"token_in": max(1, len(prompt) // 4), "token_out": max(1, len(acc) // 4),
                 "latency_ms": latency,
                 "cost": round((len(prompt) + len(acc)) / 4 / 1000 * (0.009 if route == "hosted-frontier" else 0), 6)}
        try:
            await db.model_calls.insert_one({
                "_id": uuid.uuid4().hex, "engagement_id": eid, "agent_run_id": None, "route": route,
                "model": BEDROCK_MODEL_ID if route == "hosted-frontier" else "Llama-3.1-8B-Instruct",
                "purpose": "attack_path_analysis", "task_class": "reason", "sensitivity": "internal",
                "token_in": usage["token_in"], "token_out": usage["token_out"], "cost": usage["cost"],
                "latency_ms": latency, "redaction_applied": False,
                "ts": datetime.now(timezone.utc).isoformat(),
            })
            await audit_event(eid, "agent", "attack-path-analyst", "attack_path_generated",
                              {"route": route, "paths": len(data["paths"])})
            yield f'data: {json.dumps({"done": True, "route": route, "usage": usage})}\n\n'
        except (asyncio.CancelledError, GeneratorExit):
            return

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"})
