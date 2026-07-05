"""C-09 Vulnerability & Patch Loop (v1-min): versions -> CVE/KEV -> exploitable flag -> remediate -> re-test."""
import uuid
from fastapi import APIRouter, HTTPException, Body
from typing import Optional, Dict, Any
from db import db
from store import doc_out, docs_out, get_engagement, now_iso
from audit import audit_event
from cve_data import CVE_FEED, correlate, severity_from_cvss

router = APIRouter()


def _exploitability(exposure, cve):
    # reachable if a working exploit exists / on KEV (internal or external); confirmed only after exploit approval
    if cve.get("kev") or cve.get("exploit_known"):
        return "reachable"
    return "unconfirmed"


def _reason(exposure, cve):
    bits = [f"{exposure} exposure"]
    if cve.get("kev"):
        bits.append("on CISA KEV")
    if cve.get("exploit_known"):
        bits.append("public exploit available")
    if not cve.get("kev") and not cve.get("exploit_known"):
        bits.append("no known public exploit")
    return " + ".join(bits)


async def refresh_cve_cache(actor="system", actor_id="scheduler"):
    for c in CVE_FEED:
        rec = dict(c)
        rec["_id"] = c["cve_id"]
        rec["fetched_at"] = now_iso()
        await db.cve_cache.update_one({"_id": c["cve_id"]}, {"$set": rec}, upsert=True)
    await audit_event(None, actor, actor_id, "cve_cache_refreshed", {"count": len(CVE_FEED)})
    return len(CVE_FEED)


async def correlate_engagement(engagement_id, actor="operator", actor_id="console"):
    eng = await get_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="engagement not found")
    assets = await db.assets.find({"engagement_id": engagement_id}).to_list(3000)
    created, updated = 0, 0
    await audit_event(engagement_id, actor, actor_id, "vuln_scan_started", {"assets": len(assets)})

    for a in assets:
        exposure = a.get("exposure", "unknown")
        for ver in a.get("versions", []):
            product, version = ver.get("product"), ver.get("version")
            for cve in correlate(product, version):
                key = {"engagement_id": engagement_id, "asset_id": a["_id"], "cve_refs": cve["cve_id"]}
                existing = await db.findings.find_one({"engagement_id": engagement_id, "asset_id": a["_id"],
                                                       "cve_refs": {"$in": [cve["cve_id"]]}})
                exploitability = _exploitability(exposure, cve)
                severity = severity_from_cvss(cve["cvss"])
                remediation = (f"Upgrade {product} {version} → {cve['patched_version']}. "
                               f"Apply vendor advisory {cve['cve_id']}; add compensating WAF/network controls "
                               f"until patched.")
                if existing:
                    if existing.get("status") not in ("closed", "false-positive"):
                        await db.findings.update_one({"_id": existing["_id"]},
                                                     {"$set": {"exploitability": exploitability,
                                                               "severity": severity,
                                                               "reachability_reason": _reason(exposure, cve)}})
                        updated += 1
                    continue
                fid = uuid.uuid4().hex
                finding = {
                    "_id": fid, "engagement_id": engagement_id, "asset_id": a["_id"],
                    "title": f"{cve['cve_id']}: {product} {version}",
                    "severity": severity, "status": "open",
                    "evidence_refs": [{"type": "sbom", "detail": f"{product} {version} on port {ver.get('port')}"}],
                    "cve_refs": [cve["cve_id"]], "technique_ref": "T1190",
                    "exploitability": exploitability, "reachability_reason": _reason(exposure, cve),
                    "remediation": remediation, "product": product,
                    "vulnerable_version": version, "patched_version": cve["patched_version"],
                    "cvss": cve["cvss"], "kev": cve.get("kev", False), "source": "vuln-loop",
                    "created_at": now_iso(),
                }
                await db.findings.insert_one(finding)
                created += 1
                await audit_event(engagement_id, actor, actor_id, "finding_created",
                                  {"finding_id": fid, "cve": cve["cve_id"], "severity": severity,
                                   "exploitability": exploitability})
    await audit_event(engagement_id, actor, actor_id, "vuln_scan_completed",
                      {"created": created, "updated": updated})
    return {"created": created, "updated": updated}


@router.post("/engagements/{eid}/vuln-scan")
async def vuln_scan(eid: str):
    return await correlate_engagement(eid)


@router.post("/engagements/{eid}/refresh-cve")
async def refresh_cve(eid: str):
    n = await refresh_cve_cache()
    return {"refreshed": n}


@router.get("/cve-cache")
async def get_cve_cache():
    recs = await db.cve_cache.find({}).to_list(500)
    return {"cves": docs_out(recs)}


@router.get("/engagements/{eid}/findings")
async def list_findings(eid: str):
    fs = await db.findings.find({"engagement_id": eid}).sort("created_at", -1).to_list(5000)
    return {"findings": docs_out(fs)}


@router.post("/findings/{fid}/remediate")
async def remediate(fid: str, body: Optional[Dict[str, Any]] = Body(default=None)):
    f = await db.findings.find_one({"_id": fid})
    if not f:
        raise HTTPException(status_code=404, detail="finding not found")
    # simulate operator applying the patch: bump the asset version to the patched version
    patched = f.get("patched_version")
    await db.assets.update_one(
        {"_id": f["asset_id"], "versions.product": f.get("product"), "versions.version": f.get("vulnerable_version")},
        {"$set": {"versions.$.version": patched}})
    await db.findings.update_one({"_id": fid}, {"$set": {"status": "remediating"}})
    await audit_event(f["engagement_id"], "operator", body.get("actor_id", "console") if body else "console",
                      "finding_remediation_applied", {"finding_id": fid, "patched_version": patched})
    return {"status": "remediating", "patched_version": patched}


@router.post("/findings/{fid}/retest")
async def retest(fid: str, body: Optional[Dict[str, Any]] = Body(default=None)):
    f = await db.findings.find_one({"_id": fid})
    if not f:
        raise HTTPException(status_code=404, detail="finding not found")
    asset = await db.assets.find_one({"_id": f["asset_id"]})
    still_vuln = False
    if asset:
        for ver in asset.get("versions", []):
            if ver.get("product") == f.get("product") and ver.get("version") == f.get("vulnerable_version"):
                if correlate(f.get("product"), f.get("vulnerable_version")):
                    still_vuln = True
    if still_vuln:
        await db.findings.update_one({"_id": fid}, {"$set": {"status": "retest"}})
        await audit_event(f["engagement_id"], "operator", "console", "finding_retest_failed", {"finding_id": fid})
        return {"status": "retest", "closed": False, "message": "Vulnerable version still present."}
    ev = {"type": "retest", "detail": f"Re-test passed at {now_iso()}: {f.get('product')} now patched.",
          "at": now_iso()}
    await db.findings.update_one({"_id": fid},
                                 {"$set": {"status": "closed"}, "$push": {"evidence_refs": ev}})
    await audit_event(f["engagement_id"], "operator", "console", "finding_closed_retest",
                      {"finding_id": fid, "evidence": ev})
    return {"status": "closed", "closed": True, "evidence": ev}
