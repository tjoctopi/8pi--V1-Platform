"""C-03 Tool Service Layer. Every tool call passes server-side scope_check (SEC-02) and is audited (DM-06)."""
import asyncio
import uuid
from fastapi import APIRouter, HTTPException, Body, Query
from typing import Optional, Dict, Any
from db import db
from store import doc_out, docs_out, get_engagement, get_roe, now_iso
from audit import audit_event
from scope import scope_check
from sim_tools import TOOL_REGISTRY, TOOL_BY_ID
from real_tools import run_real_tool, tool_availability

router = APIRouter()


async def execute_tool(engagement_id, tool_id, target, args=None, profile="default",
                       agent_run_id=None, intensity=None, actor="agent", actor_id=None,
                       approved=False):
    """Core scope-checked, audited tool execution. Returns the DM-06 invocation doc (as id-mapped dict)."""
    args = args or {}
    tool = TOOL_BY_ID.get(tool_id)
    if not tool:
        raise HTTPException(status_code=404, detail=f"unknown tool: {tool_id}")

    eng = await get_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="engagement not found")

    # SEC-10 kill switch
    if eng.get("halted"):
        await audit_event(engagement_id, actor, actor_id, "tool_refused_halted",
                          {"tool_id": tool_id, "target": target})
        raise HTTPException(status_code=423, detail="engagement halted (kill switch active)")

    # FR-TOOL-07: licensed tools are forward-hook only
    if not tool.get("license_verified", False):
        await audit_event(engagement_id, actor, actor_id, "tool_refused_unlicensed",
                          {"tool_id": tool_id, "target": target})
        raise HTTPException(status_code=451, detail=f"tool '{tool_id}' is licensed and not enabled in v1 (RISK-04)")

    intensity = intensity or tool["min_intensity"]
    roe = await get_roe(eng)
    check = scope_check(roe, target, tool_id=tool_id, intensity=intensity)

    # exploit-intensity actions require prior approval (SEC-06), unless invoked post-approval
    if check["allow"] and intensity == "exploit" and not approved:
        check = {"allow": False, "reason": "requires_approval"}

    inv_id = uuid.uuid4().hex
    started = now_iso()
    if not check["allow"]:
        inv = {
            "_id": inv_id, "engagement_id": engagement_id, "tool_id": tool_id, "agent_run_id": agent_run_id,
            "args": args, "target": target, "intensity": intensity, "profile": profile,
            "scope_check_result": check, "status": "refused", "started_at": started,
            "ended_at": now_iso(), "exit_status": "refused", "parsed": {}, "raw_output_ref": None,
        }
        await db.tool_invocations.insert_one(inv)
        reason = check.get("reason") or ""
        etype = "out_of_scope_attempt" if reason.startswith("target_") else "tool_refused"
        await audit_event(engagement_id, actor, actor_id, etype,
                          {"tool_id": tool_id, "target": target, "reason": reason, "invocation_id": inv_id})
        return doc_out(inv)

    # execute — real CLI binary if available and TOOL_MODE allows, otherwise deterministic sim
    result = await asyncio.to_thread(run_real_tool, tool_id, target, args)
    raw_id = uuid.uuid4().hex
    await db.tool_raw_outputs.insert_one({"_id": raw_id, "engagement_id": engagement_id, "raw": result.get("raw", "")})
    inv = {
        "_id": inv_id, "engagement_id": engagement_id, "tool_id": tool_id, "agent_run_id": agent_run_id,
        "args": args, "target": target, "intensity": intensity, "profile": profile,
        "scope_check_result": check, "status": "completed", "started_at": started,
        "ended_at": now_iso(), "exit_status": "ok", "parsed": result.get("parsed", {}),
        "raw_output_ref": raw_id, "mode": result.get("mode", "sim"),
        "cmd": result.get("cmd"),
    }
    await db.tool_invocations.insert_one(inv)
    await audit_event(engagement_id, actor, actor_id, "tool_invocation",
                      {"tool_id": tool_id, "target": target, "intensity": intensity,
                       "invocation_id": inv_id, "approved": approved, "mode": inv["mode"]})
    return doc_out(inv)


@router.get("/tools")
async def list_tools():
    avail = tool_availability()
    tools = []
    for t in TOOL_REGISTRY:
        a = avail["tools"].get(t["tool_id"], {})
        tools.append({**t, "installed": a.get("installed", False),
                      "effective_mode": a.get("effective", "sim"),
                      "binary_path": a.get("path")})
    return {"tools": tools, "tool_mode": avail["mode"]}


@router.get("/tools/availability")
async def tools_availability():
    return tool_availability()


@router.post("/tools/{tool_id}/run")
async def run_tool(tool_id: str, body: Dict[str, Any] = Body(...)):
    eid = body.get("engagement_id")
    if not eid:
        raise HTTPException(status_code=400, detail="engagement_id required")
    return await execute_tool(
        engagement_id=eid, tool_id=tool_id, target=body.get("target"),
        args=body.get("args"), profile=body.get("profile", "default"),
        agent_run_id=body.get("agent_run_id"), intensity=body.get("intensity"),
        actor="operator", actor_id=body.get("actor_id", "console"),
        approved=bool(body.get("approved", False)),
    )


@router.get("/engagements/{eid}/invocations")
async def list_invocations(eid: str, limit: int = 200):
    invs = await db.tool_invocations.find({"engagement_id": eid}).sort("started_at", -1).to_list(limit)
    return {"invocations": docs_out(invs)}


@router.get("/invocations/{inv_id}/raw")
async def get_raw(inv_id: str):
    inv = await db.tool_invocations.find_one({"_id": inv_id})
    if not inv:
        raise HTTPException(status_code=404, detail="not found")
    raw = None
    if inv.get("raw_output_ref"):
        r = await db.tool_raw_outputs.find_one({"_id": inv["raw_output_ref"]})
        raw = r["raw"] if r else None
    return {"invocation": doc_out(inv), "raw": raw}
