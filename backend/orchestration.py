"""C-07 Orchestration & Audit: engagement lifecycle, RoE binding, approval gates, kill switch, audit query."""
import hashlib
import uuid
from fastapi import APIRouter, HTTPException, Body, Query, Request
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from db import db
from store import doc_out, docs_out, get_engagement, get_roe, get_roe_by_id, now_iso, iso_in, gen_id
from audit import audit_event, verify_chain
from scope import scope_check, intensity_level
from tool_service import execute_tool

router = APIRouter()

DEFAULT_TOOLS = ["nmap"]


class EngagementCreate(BaseModel):
    name: str
    estate_seeds: List[str] = []
    created_by: str = "operator"


class RoeUpdate(BaseModel):
    scope_allowlist: List[str] = []
    scope_denylist: List[str] = []
    allowed_tools: List[str] = []
    allowed_techniques: List[str] = []
    window_start: Optional[str] = None
    window_end: Optional[str] = None
    max_intensity: str = "recon"


# ---------- core helpers (also used by the seed) ----------
async def create_engagement_core(name, seeds, created_by="operator"):
    eid = uuid.uuid4().hex
    estate_id = "est_" + eid[:12]
    rid = uuid.uuid4().hex
    roe = {
        "_id": rid, "engagement_id": eid, "version": 1,
        "scope_allowlist": seeds or [], "scope_denylist": [],
        "allowed_tools": DEFAULT_TOOLS, "allowed_techniques": [],
        "window_start": now_iso(), "window_end": iso_in(days=30),
        "max_intensity": "recon", "signed_by": None, "signed_at": None, "signature": None,
        "created_at": now_iso(),
    }
    eng = {
        "_id": eid, "name": name, "estate_id": estate_id, "roe_id": rid,
        "status": "draft", "halted": False, "archived": False, "created_by": created_by,
        "created_at": now_iso(), "closed_at": None,
        "estate": {"id": estate_id, "name": f"{name} estate", "seeds": seeds or []},
    }
    await db.roes.insert_one(roe)
    await db.engagements.insert_one(eng)
    await audit_event(eid, "operator", created_by, "engagement_created", {"name": name, "seeds": seeds})
    return eng


async def sign_roe_core(engagement_id, signed_by):
    eng = await get_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="engagement not found")
    roe = await get_roe(eng)
    if not roe:
        raise HTTPException(status_code=404, detail="roe not found")
    if roe.get("signature"):
        raise HTTPException(status_code=409, detail="RoE already signed (immutable). Create a new version to change.")
    signed_at = now_iso()
    material = f"{roe['engagement_id']}|{roe['scope_allowlist']}|{roe['allowed_tools']}|{roe['max_intensity']}|{signed_by}|{signed_at}"
    signature = hashlib.sha256(material.encode()).hexdigest()
    await db.roes.update_one({"_id": roe["_id"]},
                             {"$set": {"signed_by": signed_by, "signed_at": signed_at, "signature": signature}})
    await audit_event(engagement_id, "operator", signed_by, "roe_signed",
                      {"roe_id": roe["_id"], "signature": signature[:16] + "…"})
    return await get_roe_by_id(roe["_id"])


async def activate_core(engagement_id, actor_id="console"):
    eng = await get_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="engagement not found")
    roe = await get_roe(eng)
    if not roe or not roe.get("signature"):
        raise HTTPException(status_code=412, detail="cannot activate without a signed RoE (SEC-01)")
    await db.engagements.update_one({"_id": engagement_id}, {"$set": {"status": "active", "halted": False}})
    await audit_event(engagement_id, "operator", actor_id, "engagement_activated", {"roe_id": roe["_id"]})
    return await get_engagement(engagement_id)


async def create_approval(engagement_id, action, agent_run_id=None, requested_by="agent"):
    aid = uuid.uuid4().hex
    doc = {
        "_id": aid, "engagement_id": engagement_id, "agent_run_id": agent_run_id,
        "action": action, "status": "pending", "requested_by": requested_by,
        "created_at": now_iso(), "decided_by": None, "decided_at": None, "decision_reason": None,
        "result_invocation_id": None,
    }
    await db.approvals.insert_one(doc)
    await audit_event(engagement_id, "agent", requested_by, "approval_requested",
                      {"approval_id": aid, "action": action})
    return doc_out(doc)


# ---------- endpoints ----------
@router.get("/engagements")
async def list_engagements(include_archived: int = 0):
    q = {} if include_archived else {"archived": {"$ne": True}}
    engs = await db.engagements.find(q).sort("created_at", -1).to_list(500)
    out = []
    for e in engs:
        roe = await get_roe_by_id(e.get("roe_id"))
        findings = await db.findings.count_documents({"engagement_id": e["_id"]})
        assets = await db.assets.count_documents({"engagement_id": e["_id"]})
        pending = await db.approvals.count_documents({"engagement_id": e["_id"], "status": "pending"})
        d = doc_out(e)
        d["roe_signed"] = bool(roe and roe.get("signature"))
        d["max_intensity"] = roe.get("max_intensity") if roe else None
        d["archived"] = bool(e.get("archived"))
        d["counts"] = {"findings": findings, "assets": assets, "pending_approvals": pending}
        out.append(d)
    return {"engagements": out}


@router.post("/engagements")
async def create_engagement(body: EngagementCreate):
    eng = await create_engagement_core(body.name, body.estate_seeds, body.created_by)
    return doc_out(eng)


@router.get("/engagements/{eid}")
async def get_engagement_detail(eid: str):
    eng = await get_engagement(eid)
    if not eng:
        raise HTTPException(status_code=404, detail="engagement not found")
    roe = await get_roe(eng)
    counts = {
        "assets": await db.assets.count_documents({"engagement_id": eid}),
        "findings": await db.findings.count_documents({"engagement_id": eid}),
        "invocations": await db.tool_invocations.count_documents({"engagement_id": eid}),
        "pending_approvals": await db.approvals.count_documents({"engagement_id": eid, "status": "pending"}),
        "agent_runs": await db.agent_runs.count_documents({"engagement_id": eid}),
        "model_calls": await db.model_calls.count_documents({"engagement_id": eid}),
    }
    return {"engagement": doc_out(eng), "roe": doc_out(roe), "counts": counts}


@router.put("/engagements/{eid}/roe")
async def update_roe(eid: str, body: RoeUpdate):
    eng = await get_engagement(eid)
    if not eng:
        raise HTTPException(status_code=404, detail="engagement not found")
    roe = await get_roe(eng)
    if roe and roe.get("signature"):
        raise HTTPException(status_code=409, detail="signed RoE is immutable")
    await db.roes.update_one({"_id": roe["_id"]}, {"$set": body.model_dump()})
    await audit_event(eid, "operator", "console", "roe_updated", body.model_dump())
    return doc_out(await get_roe_by_id(roe["_id"]))


@router.post("/engagements/{eid}/roe/sign")
async def sign_roe(eid: str, body: Dict[str, Any] = Body(...)):
    roe = await sign_roe_core(eid, body.get("signed_by", "operator"))
    return doc_out(roe)


@router.post("/engagements/{eid}/activate")
async def activate(eid: str):
    return doc_out(await activate_core(eid))


@router.post("/engagements/{eid}/pause")
async def pause(eid: str):
    await db.engagements.update_one({"_id": eid}, {"$set": {"status": "paused"}})
    await audit_event(eid, "operator", "console", "engagement_paused", {})
    return doc_out(await get_engagement(eid))


@router.post("/engagements/{eid}/close")
async def close(eid: str):
    await db.engagements.update_one({"_id": eid}, {"$set": {"status": "closed", "closed_at": now_iso()}})
    await audit_event(eid, "operator", "console", "engagement_closed", {})
    return doc_out(await get_engagement(eid))


@router.post("/engagements/{eid}/halt")
async def halt(eid: str, body: Optional[Dict[str, Any]] = Body(default=None)):
    """SEC-10 kill switch: immediately stops all agent/tool activity for the engagement."""
    actor_id = (body or {}).get("actor_id", "console")
    await db.engagements.update_one({"_id": eid}, {"$set": {"halted": True, "status": "paused"}})
    # cancel any pending approvals
    await db.approvals.update_many({"engagement_id": eid, "status": "pending"},
                                   {"$set": {"status": "cancelled", "decision_reason": "engagement_halted"}})
    await db.agent_runs.update_many({"engagement_id": eid, "status": "running"},
                                    {"$set": {"status": "halted"}})
    await audit_event(eid, "operator", actor_id, "human_halt", {"kill_switch": True})
    return {"halted": True}


@router.post("/engagements/{eid}/resume")
async def resume(eid: str):
    await db.engagements.update_one({"_id": eid}, {"$set": {"halted": False, "status": "active"}})
    await audit_event(eid, "operator", "console", "engagement_resumed", {})
    return {"halted": False}


@router.post("/engagements/{eid}/archive")
async def archive_engagement(eid: str):
    eng = await get_engagement(eid)
    if not eng:
        raise HTTPException(status_code=404, detail="engagement not found")
    await db.engagements.update_one({"_id": eid}, {"$set": {"archived": True}})
    await audit_event(eid, "operator", "console", "engagement_archived", {})
    return {"archived": True}


@router.post("/engagements/{eid}/unarchive")
async def unarchive_engagement(eid: str):
    eng = await get_engagement(eid)
    if not eng:
        raise HTTPException(status_code=404, detail="engagement not found")
    await db.engagements.update_one({"_id": eid}, {"$set": {"archived": False}})
    await audit_event(eid, "operator", "console", "engagement_unarchived", {})
    return {"archived": False}


@router.get("/engagements/{eid}/audit")
async def query_audit(eid: str, actor: Optional[str] = None, event_type: Optional[str] = None, limit: int = 500):
    q = {"engagement_id": eid}
    if actor:
        q["actor"] = actor
    if event_type:
        q["event_type"] = event_type
    events = await db.audit_events.find(q).sort("seq", -1).to_list(limit)
    return {"events": docs_out(events)}


@router.get("/engagements/{eid}/audit/verify")
async def audit_verify(eid: str):
    return await verify_chain(eid)


@router.get("/engagements/{eid}/approvals")
async def list_approvals(eid: str, status: Optional[str] = None):
    q = {"engagement_id": eid}
    if status:
        q["status"] = status
    aps = await db.approvals.find(q).sort("created_at", -1).to_list(500)
    return {"approvals": docs_out(aps)}


@router.post("/approvals/{aid}/approve")
async def approve(aid: str, request: Request, body: Dict[str, Any] = Body(default={})):
    """FR-ORCH-05 / SEC-06: only an approver may release a blocked action; the action then executes.
    Role is read from the JWT — client-supplied `role` is ignored."""
    from auth import get_current_user, role_at_least
    user = await get_current_user(request)
    if not role_at_least(user, "approver"):
        raise HTTPException(status_code=403, detail="only 'approver' or 'admin' may approve (RBAC)")
    approver = user["email"]
    ap = await db.approvals.find_one({"_id": aid})
    if not ap:
        raise HTTPException(status_code=404, detail="approval not found")
    if ap["status"] != "pending":
        raise HTTPException(status_code=409, detail=f"approval is {ap['status']}")
    action = ap["action"]
    await db.approvals.update_one({"_id": aid}, {"$set": {"status": "approved", "decided_by": approver,
                                                          "decided_at": now_iso()}})
    await audit_event(ap["engagement_id"], "approver", approver, "approval_granted",
                      {"approval_id": aid, "action": action})
    # execute the released exploit-intensity tool action
    inv = await execute_tool(
        engagement_id=ap["engagement_id"], tool_id=action["tool_id"], target=action["target"],
        args=action.get("args"), intensity=action.get("intensity", "exploit"),
        agent_run_id=ap.get("agent_run_id"), actor="agent", actor_id="offensive-agent", approved=True)
    await db.approvals.update_one({"_id": aid}, {"$set": {"result_invocation_id": inv.get("id")}})
    # confirm the linked finding if the exploit succeeded
    fid = action.get("finding_id")
    if fid and inv.get("status") == "completed" and inv.get("parsed", {}).get("injectable"):
        ev = {"type": "exploit", "detail": f"Confirmed via {action['tool_id']}: {inv['parsed'].get('technique')}",
              "invocation_id": inv.get("id"), "at": now_iso()}
        await db.findings.update_one({"_id": fid},
                                     {"$set": {"exploitability": "confirmed", "severity": "crit"},
                                      "$push": {"evidence_refs": ev}})
        await audit_event(ap["engagement_id"], "agent", "offensive-agent", "exploit_confirmed",
                          {"finding_id": fid, "invocation_id": inv.get("id")})
    return {"status": "approved", "invocation": inv}


@router.post("/approvals/{aid}/deny")
async def deny(aid: str, request: Request, body: Dict[str, Any] = Body(default={})):
    from auth import get_current_user, role_at_least
    user = await get_current_user(request)
    if not role_at_least(user, "approver"):
        raise HTTPException(status_code=403, detail="only 'approver' or 'admin' may deny (RBAC)")
    approver = user["email"]
    ap = await db.approvals.find_one({"_id": aid})
    if not ap or ap["status"] != "pending":
        raise HTTPException(status_code=409, detail="approval not pending")
    await db.approvals.update_one({"_id": aid}, {"$set": {"status": "denied", "decided_by": approver,
                                                          "decided_at": now_iso(),
                                                          "decision_reason": body.get("reason", "")}})
    await audit_event(ap["engagement_id"], "approver", approver, "approval_denied",
                      {"approval_id": aid, "reason": body.get("reason", "")})
    return {"status": "denied"}


@router.get("/stats")
async def stats():
    engs = await db.engagements.find({}).to_list(1000)
    by_status = {}
    for e in engs:
        by_status[e["status"]] = by_status.get(e["status"], 0) + 1
    findings = await db.findings.find({}).to_list(10000)
    sev = {}
    for f in findings:
        if f.get("status") in ("closed", "false-positive"):
            continue
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    model_calls = await db.model_calls.find({}).to_list(20000)
    total_cost = round(sum(c.get("cost", 0) for c in model_calls), 4)
    return {
        "engagements": len(engs),
        "engagements_by_status": by_status,
        "assets": await db.assets.count_documents({}),
        "findings_open": sum(sev.values()),
        "findings_by_severity": sev,
        "tool_invocations": await db.tool_invocations.count_documents({}),
        "pending_approvals": await db.approvals.count_documents({"status": "pending"}),
        "model_calls": len(model_calls),
        "model_spend": total_cost,
        "agents": await db.agents.count_documents({}),
    }
