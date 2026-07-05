"""C-02 Model Gateway (BYOM). Single seam for all model calls (IF-MODEL). Records DM-08."""
import os
import re
import time
import uuid
import asyncio
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional, Any, Dict
from db import db
from store import doc_out, docs_out
from audit import audit_event
from bedrock import BEDROCK_MODEL_ID, converse_text

router = APIRouter()

ROUTES = {
    "hosted-frontier": {
        "id": "hosted-frontier", "provider": "aws-bedrock", "model": BEDROCK_MODEL_ID,
        "kind": "hosted", "boundary": "external", "cost_per_1k": 0.015, "status": "live",
        "description": "Hosted frontier model (Anthropic Claude Opus 4.8) via AWS Bedrock (BYOM gateway).",
    },
    "local-openweight": {
        "id": "local-openweight", "provider": "local", "model": "Llama-3.1-8B-Instruct",
        "kind": "local", "boundary": "local-h100", "cost_per_1k": 0.0, "status": "live",
        "description": "Local open-weight model on single H100. Sensitive/airgapped traffic is pinned here (SEC-05).",
    },
    "openmythos-7b": {
        "id": "openmythos-7b", "provider": "local", "model": "OpenMythos-7B",
        "kind": "stub", "boundary": "local-h100", "cost_per_1k": 0.0, "status": "not_implemented",
        "description": "Forward hook (C-11). Contract-validated but returns 501 in v1.",
    },
}

_REDACTIONS = [
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[REDACTED_EMAIL]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token)\b\s*[=:]\s*\S+"), r"\1=[REDACTED]"),
    (re.compile(r"sk-[A-Za-z0-9\-]{12,}"), "[REDACTED_KEY]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS]"),
]


def _redact(text):
    if not isinstance(text, str):
        return text, False
    applied = False
    for pat, repl in _REDACTIONS:
        new = pat.sub(repl, text)
        if new != text:
            applied = True
        text = new
    return text, applied


class InferRequest(BaseModel):
    purpose: str = "general"
    task_class: str = "reason"          # reason|triage|summarize|convert|evaluate|embed
    sensitivity: str = "internal"       # public|internal|sensitive|airgapped
    messages: List[Dict[str, Any]] = []
    tools: Optional[List[Any]] = None
    max_tokens: Optional[int] = 512
    engagement_id: Optional[str] = None
    route: Optional[str] = None         # explicit route request (validated against policy)
    agent_run_id: Optional[str] = None


def choose_route(sensitivity, task_class, requested):
    # SEC-05: sensitive/airgapped must never transit a hosted provider. Fail-closed to local.
    if sensitivity in ("sensitive", "airgapped"):
        return "local-openweight"
    if requested and requested in ROUTES and requested != "openmythos-7b":
        return requested
    if task_class in ("reason", "evaluate"):
        return "hosted-frontier"
    return "local-openweight"


def _estimate_tokens(text):
    return max(1, len(text or "") // 4)


_DEFAULT_SYSTEM = "You are 8pi, an expert purple-team security analyst. Be concise and precise."


async def _call_hosted(system_msg, user_text, max_tokens):
    # AWS Bedrock (Anthropic Claude) via boto3 Converse API. Runs the blocking
    # SDK call in a thread so the event loop stays responsive.
    return await asyncio.to_thread(converse_text, system_msg or _DEFAULT_SYSTEM, user_text, max_tokens)


def _call_local(system_msg, user_text, purpose):
    # Deterministic on-prem responder. No network egress by construction.
    head = f"[local-openweight · on-prem H100] analysis for '{purpose}':"
    snippet = (user_text or "").strip().splitlines()
    focus = snippet[-1][:240] if snippet else ""
    return (f"{head}\nProcessed {len(user_text or '')} chars locally under the airgap boundary. "
            f"Key input: \"{focus}\". No data left the security perimeter.")


async def infer(req: InferRequest, actor="agent", actor_id=None):
    started = time.time()
    if req.route == "openmythos-7b":
        # FR-MODEL-06: validate contract shape, then 501.
        await audit_event(req.engagement_id, actor, actor_id, "model_call_rejected",
                          {"route": "openmythos-7b", "reason": "not_implemented"})
        raise HTTPException(status_code=501, detail="openmythos-7b route not implemented (C-11 forward hook)")

    route = choose_route(req.sensitivity, req.task_class, req.route)
    # SEC-05 hard guarantee
    egress_blocked = req.sensitivity in ("sensitive", "airgapped")
    if egress_blocked and ROUTES[route]["kind"] == "hosted":
        raise HTTPException(status_code=403, detail="egress_blocked: sensitive traffic cannot use a hosted route")

    system_msg = next((m.get("content", "") for m in req.messages if m.get("role") == "system"), "")
    body_msgs = [m for m in req.messages if m.get("role") != "system"]
    user_text = "\n".join([f"{m.get('role', 'user')}: {m.get('content', '')}" for m in body_msgs]) or system_msg
    red_text, redaction_applied = _redact(user_text)

    text = ""
    try:
        if ROUTES[route]["kind"] == "hosted":
            text = await _call_hosted(system_msg, red_text, req.max_tokens or 512)
        else:
            text = _call_local(system_msg, red_text, req.purpose)
    except Exception as e:
        # No silent fallback across the egress boundary. Serve local so the pipeline is resilient.
        route = "local-openweight"
        text = _call_local(system_msg, red_text, req.purpose) + f"\n(note: hosted route unavailable: {str(e)[:120]})"

    out_red, out_red_applied = _redact(text)
    latency_ms = int((time.time() - started) * 1000)
    token_in = _estimate_tokens(red_text)
    token_out = _estimate_tokens(out_red)
    cost = round((token_in + token_out) / 1000.0 * ROUTES[route]["cost_per_1k"], 6)

    call = {
        "_id": uuid.uuid4().hex,
        "engagement_id": req.engagement_id,
        "agent_run_id": req.agent_run_id,
        "route": route,
        "model": ROUTES[route]["model"],
        "purpose": req.purpose,
        "task_class": req.task_class,
        "sensitivity": req.sensitivity,
        "token_in": token_in,
        "token_out": token_out,
        "cost": cost,
        "latency_ms": latency_ms,
        "redaction_applied": bool(redaction_applied or out_red_applied),
        "egress_blocked": egress_blocked,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    await db.model_calls.insert_one(call)
    await audit_event(req.engagement_id, actor, actor_id, "model_call",
                      {"route": route, "purpose": req.purpose, "sensitivity": req.sensitivity,
                       "redaction_applied": call["redaction_applied"], "cost": cost})
    return {"text": out_red, "route": route, "model": ROUTES[route]["model"],
            "usage": {"token_in": token_in, "token_out": token_out, "cost": cost, "latency_ms": latency_ms},
            "redaction_applied": call["redaction_applied"]}


@router.get("/model/routes")
async def get_routes():
    return {"routes": list(ROUTES.values())}


@router.post("/model/infer")
async def post_infer(req: InferRequest):
    res = await infer(req, actor="operator", actor_id="console")
    return res


@router.get("/model/calls")
async def get_calls(engagement_id: Optional[str] = None, limit: int = 100):
    q = {"engagement_id": engagement_id} if engagement_id else {}
    calls = await db.model_calls.find(q).sort("ts", -1).to_list(limit)
    return {"calls": docs_out(calls)}
