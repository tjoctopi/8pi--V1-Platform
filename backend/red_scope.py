"""Red Scope — incident hub aggregation + adversarial attack designer (AI → agent registry)."""
import json
import re
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from db import db
from store import doc_out, docs_out
from model_gateway import infer, InferRequest
from agent_runtime import AgentCreate, create_agent_core

router = APIRouter()

VALID_TOOLS = {"nmap", "nikto", "dirbust", "wpscan", "sqlmap"}
VALID_ROLES = {"offensive", "defensive", "recon"}
VALID_INTENSITY = {"recon", "safe-active", "exploit"}

ATTACK_SYSTEM = (
    "You are 8pi Red Scope, an offensive-operations copilot for AUTHORIZED purple-team engagements. "
    "The operator describes an attack objective in natural language. Your job:\n"
    "1. Ask a brief clarifying question ONLY when essential (target, goal, or intensity).\n"
    "2. As soon as you have enough, propose ONE concrete, runnable agent configuration.\n"
    "Allowed tools ONLY: nmap, nikto, dirbust, wpscan, sqlmap. "
    "Roles: offensive | defensive | recon. Intensity ladder: recon < safe-active < exploit.\n"
    "Keep prose concise (2-4 sentences). When (and only when) you propose a config, END your message "
    "with a fenced json block exactly like:\n"
    "```json\n"
    '{"name":"web-sqli-agent","role":"offensive","max_intensity":"exploit","tools":["nmap","sqlmap"],'
    '"target":"app.example.com","technique":"OWASP A03 Injection","rationale":"why this chain"}\n'
    "```"
)


def _sanitize_draft(d: Dict[str, Any]) -> Dict[str, Any]:
    role = d.get("role") if d.get("role") in VALID_ROLES else "offensive"
    intensity = d.get("max_intensity") if d.get("max_intensity") in VALID_INTENSITY else "safe-active"
    tools = [t for t in (d.get("tools") or []) if t in VALID_TOOLS] or ["nmap"]
    return {
        "name": (str(d.get("name") or "red-scope-agent")).strip()[:60],
        "role": role,
        "max_intensity": intensity,
        "tools": tools,
        "target": (str(d.get("target") or "")).strip()[:200],
        "technique": (str(d.get("technique") or "")).strip()[:160],
        "rationale": (str(d.get("rationale") or "")).strip()[:500],
    }


def _extract_draft(text: str):
    draft = None
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
    if not m:
        m = re.search(r"(\{[^{}]*\"role\"[^{}]*\})", text, re.DOTALL)
    if not m:
        return text.strip(), None
    try:
        draft = _sanitize_draft(json.loads(m.group(1)))
    except Exception:
        return text.strip(), None
    clean = text.replace(m.group(0), "").strip()
    if not clean:
        clean = f"Proposed a **{draft['role']}** agent at **{draft['max_intensity']}** intensity. Review and save to the registry."
    return clean, draft


# ---------- incident aggregation ----------
@router.get("/red-scope")
async def red_scope_feed():
    eng_map = {e["_id"]: e.get("name") for e in await db.engagements.find({}).to_list(1000)}

    halted = await db.engagements.find({"halted": True}).sort("created_at", -1).to_list(200)

    findings = await db.findings.find({
        "$or": [{"severity": "crit"}, {"exploitability": "confirmed"}],
        "status": {"$nin": ["closed", "false-positive"]},
    }).sort("created_at", -1).to_list(200)

    approvals = await db.approvals.find({
        "status": "pending", "action.intensity": "exploit",
    }).sort("created_at", -1).to_list(200)

    asset_ids = list({f.get("asset_id") for f in findings if f.get("asset_id")})
    asset_map = {}
    if asset_ids:
        for a in await db.assets.find({"_id": {"$in": asset_ids}}).to_list(1000):
            ident = a.get("identifiers", {})
            asset_map[a["_id"]] = ident.get("url") or ident.get("host") or ident.get("ip")

    f_out = []
    for f in findings:
        d = doc_out(f)
        d["engagement_name"] = eng_map.get(f.get("engagement_id"))
        d["target"] = asset_map.get(f.get("asset_id"))
        f_out.append(d)

    a_out = []
    for a in approvals:
        d = doc_out(a)
        d["engagement_name"] = eng_map.get(a.get("engagement_id"))
        a_out.append(d)

    return {
        "halted_engagements": docs_out(halted),
        "critical_findings": f_out,
        "exploit_approvals": a_out,
        "counts": {
            "halted": len(halted),
            "critical_findings": len(f_out),
            "exploit_approvals": len(a_out),
        },
    }


# ---------- adversary copilot ----------
class RedScopeChatRequest(BaseModel):
    message: str = ""
    history: List[Dict[str, Any]] = []
    context: List[Dict[str, Any]] = []
    engagement_id: Optional[str] = None


@router.post("/red-scope/chat")
async def red_scope_chat(req: RedScopeChatRequest, request: Request):
    from auth import get_current_user, role_at_least
    user = await get_current_user(request)
    if not role_at_least(user, "operator"):
        raise HTTPException(status_code=403, detail="operator role required to use the adversary copilot (RBAC)")
    msgs: List[Dict[str, Any]] = [{"role": "system", "content": ATTACK_SYSTEM}]
    for h in req.history[-10:]:
        if h.get("role") in ("user", "assistant"):
            msgs.append({"role": h["role"], "content": h.get("content", "")})

    user_content = (req.message or "").strip()
    if req.context:
        lines = []
        for c in req.context[:20]:
            kind = str(c.get("kind", "item"))
            label = str(c.get("label", "")).strip()
            detail = str(c.get("detail", "")).strip()
            lines.append(f"- [{kind}] {label}" + (f" — {detail}" if detail else ""))
        block = ("Attached live targets/signals from the incident hub — design the attack chain / "
                 "pen-test agent around these specific items:\n" + "\n".join(lines))
        if user_content:
            user_content = f"{user_content}\n\n{block}"
        else:
            user_content = f"{block}\n\nPropose the most effective, in-scope attack chain / pen-test agent for these targets."
    msgs.append({"role": "user", "content": user_content})

    res = await infer(InferRequest(
        purpose="red_scope_attack_design", task_class="reason", sensitivity="internal",
        engagement_id=req.engagement_id, max_tokens=550, messages=msgs,
    ), actor="operator", actor_id="red-scope")

    reply, draft = _extract_draft(res.get("text", ""))
    return {"reply": reply, "draft": draft, "route": res.get("route")}


class RedScopeSaveRequest(BaseModel):
    name: str
    role: str = "offensive"
    max_intensity: str = "safe-active"
    tools: List[str] = []
    target: Optional[str] = None
    technique: Optional[str] = None
    rationale: Optional[str] = None


@router.post("/red-scope/agents")
async def red_scope_save_agent(req: RedScopeSaveRequest, request: Request):
    from auth import get_current_user, role_at_least
    user = await get_current_user(request)
    if not role_at_least(user, "operator"):
        raise HTTPException(status_code=403, detail="operator role required to save an agent (RBAC)")
    clean = _sanitize_draft(req.model_dump())
    body = AgentCreate(
        name=clean["name"], role=clean["role"], max_intensity=clean["max_intensity"],
        tools=clean["tools"], owner="red-scope",
    )
    doc = await create_agent_core(body, origin="red-scope")
    await db.agents.update_one({"_id": doc["_id"]}, {"$set": {"red_scope_brief": {
        "target": clean["target"], "technique": clean["technique"], "rationale": clean["rationale"],
    }}})
    return doc_out(await db.agents.find_one({"_id": doc["_id"]}))
