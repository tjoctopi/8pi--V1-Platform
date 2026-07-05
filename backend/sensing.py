"""C-01 Sensing & Inventory. Discovers in-scope assets via the tool boundary; writes the asset graph (DM-03)."""
import uuid
import ipaddress
from fastapi import APIRouter, HTTPException, Body
from typing import Optional, Dict, Any
from db import db
from store import doc_out, docs_out, get_engagement, get_roe, now_iso
from audit import audit_event
from scope import scope_check, host_of, _is_cidr
from tool_service import execute_tool

router = APIRouter()


def _exposure_for(target):
    h = host_of(target)
    try:
        ip = ipaddress.ip_address(h)
        return "internal" if ip.is_private else "external"
    except Exception:
        # hostnames/urls default to external exposure unless clearly internal
        if h.endswith(".local") or h.endswith(".internal") or h.startswith("10.") or h.startswith("192.168."):
            return "internal"
        return "external"


async def _upsert_asset(engagement_id, estate_id, atype, identifiers, versions, exposure, parent=None):
    ident_key = identifiers.get("url") or identifiers.get("host") or identifiers.get("ip")
    if atype == "service":
        # services are unique per (host, port) — not just host
        match = {"engagement_id": engagement_id, "type": "service",
                 "identifiers.host": identifiers.get("host"), "identifiers.port": identifiers.get("port")}
    else:
        match = {"engagement_id": engagement_id, "type": atype,
                 "$or": [{"identifiers.url": ident_key},
                         {"identifiers.host": ident_key},
                         {"identifiers.ip": ident_key}]}
    existing = await db.assets.find_one(match)
    ts = now_iso()
    if existing:
        await db.assets.update_one({"_id": existing["_id"]},
                                   {"$set": {"last_seen": ts, "versions": versions or existing.get("versions", []),
                                             "exposure": exposure}})
        return existing["_id"]
    aid = uuid.uuid4().hex
    doc = {
        "_id": aid, "estate_id": estate_id, "engagement_id": engagement_id, "type": atype,
        "identifiers": identifiers, "versions": versions or [], "first_seen": ts, "last_seen": ts,
        "attributes": {"parent": parent} if parent else {}, "exposure": exposure,
    }
    await db.assets.insert_one(doc)
    return aid


async def run_sensing(engagement_id, actor="operator", actor_id="console"):
    eng = await get_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="engagement not found")
    if eng.get("halted"):
        raise HTTPException(status_code=423, detail="engagement halted")
    roe = await get_roe(eng)
    if not roe or not roe.get("signature"):
        raise HTTPException(status_code=412, detail="signed RoE required before sensing (SEC-01)")

    estate_id = eng.get("estate_id")
    raw_seeds = (eng.get("estate", {}) or {}).get("seeds", [])
    # expand CIDR seeds into a few representative in-range hosts (a CIDR itself is not scannable)
    seeds = []
    for s in raw_seeds:
        if "/" in s and _is_cidr(s):
            try:
                net = ipaddress.ip_network(s, strict=False)
                hosts = list(net.hosts())
                for ip in hosts[9:13]:  # a small representative slice
                    seeds.append(str(ip))
            except Exception:
                seeds.append(s)
        else:
            seeds.append(s)
    discovered, rejected = [], []
    await audit_event(engagement_id, actor, actor_id, "sensing_run_started", {"seeds": seeds})

    for seed in seeds:
        chk = scope_check(roe, seed, tool_id="nmap", intensity="recon")
        if not chk["allow"]:
            rejected.append({"seed": seed, "reason": chk["reason"]})
            await audit_event(engagement_id, actor, actor_id, "sensing_seed_rejected",
                              {"seed": seed, "reason": chk["reason"]})
            continue
        inv = await execute_tool(engagement_id, "nmap", seed, intensity="recon",
                                 actor="agent", actor_id="recon-sensing")
        if inv.get("status") != "completed":
            rejected.append({"seed": seed, "reason": inv.get("scope_check_result", {}).get("reason", "refused")})
            continue
        parsed = inv.get("parsed", {})
        exposure = _exposure_for(seed)
        is_web = "://" in seed
        host_ident = {"url": seed} if is_web else ({"ip": seed} if _is_ip(seed) else {"host": seed})
        host_type = "webapp" if is_web else "host"
        host_versions = [{"product": p["product"], "version": p["version"], "port": p["port"]}
                         for p in parsed.get("ports", [])]
        host_id = await _upsert_asset(engagement_id, estate_id, host_type, host_ident,
                                      host_versions, exposure)
        discovered.append(host_id)
        for p in parsed.get("ports", []):
            svc_id = await _upsert_asset(
                engagement_id, estate_id, "service",
                {"host": host_of(seed), "port": p["port"], "service": p["service"]},
                [{"product": p["product"], "version": p["version"], "port": p["port"]}],
                exposure, parent=host_id)
            discovered.append(svc_id)

    await audit_event(engagement_id, actor, actor_id, "sensing_run_completed",
                      {"assets_touched": len(discovered), "rejected": len(rejected)})
    return {"assets_touched": len(set(discovered)), "rejected": rejected}


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False


@router.post("/engagements/{eid}/sense")
async def sense(eid: str, body: Optional[Dict[str, Any]] = Body(default=None)):
    return await run_sensing(eid)


@router.get("/engagements/{eid}/assets")
async def list_assets(eid: str):
    assets = await db.assets.find({"engagement_id": eid}).sort("first_seen", 1).to_list(3000)
    return {"assets": docs_out(assets)}


@router.get("/engagements/{eid}/assets/{aid}")
async def asset_detail(eid: str, aid: str):
    asset = await db.assets.find_one({"_id": aid, "engagement_id": eid})
    if not asset:
        raise HTTPException(status_code=404, detail="asset not found")
    findings = await db.findings.find({"engagement_id": eid, "asset_id": aid}).to_list(500)
    parent_id = (asset.get("attributes") or {}).get("parent")
    parent = await db.assets.find_one({"_id": parent_id}) if parent_id else None
    children = await db.assets.find({"engagement_id": eid, "attributes.parent": aid}).to_list(500)
    # tool invocations that targeted this asset's identifier
    ident = asset.get("identifiers", {})
    key = ident.get("url") or ident.get("host") or ident.get("ip")
    invs = await db.tool_invocations.find({"engagement_id": eid, "target": key}).sort("started_at", -1).to_list(50)
    return {
        "asset": doc_out(asset),
        "findings": docs_out(findings),
        "parent": doc_out(parent),
        "children": docs_out(children),
        "invocations": docs_out(invs),
    }
