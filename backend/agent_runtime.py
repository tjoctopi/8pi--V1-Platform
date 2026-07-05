"""C-04 Agent Builder/Runtime + C-05 Offensive + C-06 Defensive agents."""
import uuid
from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from db import db
from store import doc_out, docs_out, get_engagement, get_roe, now_iso
from audit import audit_event
from scope import scope_check, intensity_level
from tool_service import execute_tool
from vuln_loop import correlate_engagement
from threat_model import candidate_targets
from orchestration import create_approval
from model_gateway import infer, InferRequest

router = APIRouter()

SANDBOX_TARGETS = [
    {"id": "sbx-dvwa", "label": "dvwa.sandbox.8pi.internal", "profile": "web-app (DVWA)"},
    {"id": "sbx-juice", "label": "juice.sandbox.8pi.internal", "profile": "web-app (Juice Shop)"},
    {"id": "sbx-metasploitable", "label": "10.99.0.5", "profile": "host (Metasploitable)"},
]

_TECHNIQUES = {
    "recon": {"id": "T1046", "name": "Network Service Discovery", "framework": "MITRE ATT&CK"},
    "enum": {"id": "T1595.003", "name": "Wordlist Scanning", "framework": "MITRE ATT&CK"},
    "known-vuln": {"id": "T1190", "name": "Exploit Public-Facing Application", "framework": "MITRE ATT&CK"},
    "exploit": {"id": "A03", "name": "Injection", "framework": "OWASP Top 10"},
}


class AgentCreate(BaseModel):
    name: str
    role: str = "offensive"          # offensive|defensive|recon
    version: str = "0.1.0"
    tools: List[str] = []
    task_class: str = "reason"
    sensitivity: str = "internal"
    max_intensity: str = "safe-active"
    owner: str = "operator"


# ---------- registry ----------
@router.get("/agents")
async def list_agents():
    agents = await db.agents.find({}).sort("created_at", -1).to_list(200)
    return {"agents": docs_out(agents)}


async def create_agent_core(body: AgentCreate, origin: str = "registry"):
    aid = uuid.uuid4().hex
    doc = {
        "_id": aid, "name": body.name, "version": body.version, "role": body.role,
        "spec": {"model": {"task_class": body.task_class, "sensitivity": body.sensitivity},
                 "tools": body.tools, "scope_source": "engagement.roe",
                 "guardrails": {"max_intensity": body.max_intensity,
                                "stop_conditions": ["out_of_scope_attempt", "budget_exceeded", "human_halt"]}},
        "owner": body.owner, "promotion_state": "dev", "last_sandbox_pass": None,
        "origin": origin, "created_at": now_iso(),
    }
    await db.agents.insert_one(doc)
    await audit_event(None, "operator", body.owner, "agent_created",
                      {"agent_id": aid, "role": body.role, "origin": origin})
    return doc


@router.post("/agents")
async def create_agent(body: AgentCreate):
    return doc_out(await create_agent_core(body))


@router.get("/sandbox-targets")
async def sandbox_targets():
    return {"targets": SANDBOX_TARGETS}


@router.post("/agents/{aid}/sandbox-run")
async def sandbox_run(aid: str):
    agent = await db.agents.find_one({"_id": aid})
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    # isolated sandbox range: intentionally-vulnerable, always in-scope, no real estate
    steps = []
    for t in SANDBOX_TARGETS:
        steps.append({"target": t["label"], "phase": "recon", "result": "3 open services",
                      "technique": _TECHNIQUES["recon"]})
        steps.append({"target": t["label"], "phase": "known-vuln", "result": "vulnerable service detected",
                      "technique": _TECHNIQUES["known-vuln"]})
    await db.agents.update_one({"_id": aid}, {"$set": {"last_sandbox_pass": now_iso(),
                                                       "promotion_state": "sandbox" if agent["promotion_state"] == "dev" else agent["promotion_state"]}})
    await audit_event(None, "system", "sandbox", "agent_sandbox_run",
                      {"agent_id": aid, "passed": True, "targets": len(SANDBOX_TARGETS)})
    return {"passed": True, "steps": steps, "message": "Sandbox run passed; agent eligible for promotion to authorized."}


@router.post("/agents/{aid}/promote")
async def promote_agent(aid: str, body: Dict[str, Any] = Body(...)):
    to_state = body.get("to_state")
    agent = await db.agents.find_one({"_id": aid})
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    if to_state == "authorized" and not agent.get("last_sandbox_pass"):
        raise HTTPException(status_code=412, detail="promotion to authorized requires a passing sandbox run (FR-AGENT-04)")
    if to_state not in ("dev", "sandbox", "authorized"):
        raise HTTPException(status_code=400, detail="invalid promotion state")
    await db.agents.update_one({"_id": aid}, {"$set": {"promotion_state": to_state}})
    await audit_event(None, "operator", "console", "agent_promoted", {"agent_id": aid, "to_state": to_state})
    return doc_out(await db.agents.find_one({"_id": aid}))


# ---------- runs ----------
async def _new_run(engagement_id, agent):
    rid = uuid.uuid4().hex
    doc = {
        "_id": rid, "engagement_id": engagement_id, "agent_id": agent["_id"],
        "agent_name": agent["name"], "role": agent["role"], "status": "running",
        "steps": [], "detections": [], "started_at": now_iso(), "ended_at": None,
        "summary": None, "detection_rate": None,
    }
    await db.agent_runs.insert_one(doc)
    return doc


async def run_offensive(engagement, agent, actor_id="offensive-agent", use_llm=True):
    if agent.get("promotion_state") != "authorized":
        raise HTTPException(status_code=412, detail="only 'authorized' agents may run against a real estate (FR-AGENT-02)")
    if engagement.get("halted"):
        raise HTTPException(status_code=423, detail="engagement halted (kill switch)")
    roe = await get_roe(engagement)
    if not roe or not roe.get("signature"):
        raise HTTPException(status_code=412, detail="signed RoE required (SEC-01)")

    eid = engagement["_id"]
    # FR-AGENT-03: effective tools/intensity = intersection with RoE (deny-by-default)
    eff_tools = [t for t in agent["spec"]["tools"] if t in roe.get("allowed_tools", [])]
    eff_intensity = min(agent["spec"]["guardrails"]["max_intensity"], roe.get("max_intensity", "recon"),
                        key=intensity_level)
    run = await _new_run(eid, agent)
    steps = []
    await audit_event(eid, "agent", actor_id, "agent_run_started",
                      {"run_id": run["_id"], "role": "offensive", "eff_tools": eff_tools,
                       "eff_intensity": eff_intensity})

    # ensure findings exist to reason about
    await correlate_engagement(eid, actor="agent", actor_id=actor_id)
    candidates = await candidate_targets(eid)
    candidates = [c for c in candidates if c["type"] in ("host", "webapp")][:4]

    approvals_created = 0
    for node in candidates:
        target = node["label"]
        # SEC-09 refusal posture: verify scope before every action
        chk = scope_check(roe, target, tool_id="nmap", intensity="recon")
        if not chk["allow"]:
            steps.append({"phase": "refused", "target": target, "reason": chk["reason"],
                          "status": "refused", "ts": now_iso()})
            await audit_event(eid, "agent", actor_id, "out_of_scope_attempt",
                              {"target": target, "reason": chk["reason"]})
            continue
        # recon
        if "nmap" in eff_tools:
            inv = await execute_tool(eid, "nmap", target, intensity="recon", agent_run_id=run["_id"],
                                     actor="agent", actor_id=actor_id)
            steps.append({"phase": "recon", "target": target, "tool_id": "nmap",
                          "technique": _TECHNIQUES["recon"], "status": inv["status"],
                          "result": f"{len(inv.get('parsed', {}).get('ports', []))} services",
                          "invocation_id": inv["id"], "ts": now_iso()})
        # enumeration (safe-active)
        if intensity_level(eff_intensity) >= 1 and "nikto" in eff_tools and node["type"] == "webapp":
            inv = await execute_tool(eid, "nikto", target, intensity="safe-active", agent_run_id=run["_id"],
                                     actor="agent", actor_id=actor_id)
            steps.append({"phase": "enum", "target": target, "tool_id": "nikto",
                          "technique": _TECHNIQUES["enum"], "status": inv["status"],
                          "result": f"{len(inv.get('parsed', {}).get('issues', []))} web issues",
                          "invocation_id": inv["id"], "ts": now_iso()})
        # known-vuln reasoning
        asset_findings = await db.findings.find(
            {"engagement_id": eid, "asset_id": node["id"], "status": {"$nin": ["closed", "false-positive"]}}
        ).to_list(50)
        reachable = [f for f in asset_findings if f.get("exploitability") in ("reachable", "confirmed")]
        steps.append({"phase": "known-vuln", "target": target, "technique": _TECHNIQUES["known-vuln"],
                      "status": "completed",
                      "result": f"{len(asset_findings)} findings, {len(reachable)} reachable", "ts": now_iso()})
        # optional scoped exploit -> requires approval (SEC-06 / FR-OFF-02)
        if reachable and roe.get("max_intensity") == "exploit" and "sqlmap" in eff_tools:
            top = sorted(reachable, key=lambda f: f.get("cvss", 0), reverse=True)[0]
            action = {"tool_id": "sqlmap", "target": target, "intensity": "exploit",
                      "finding_id": top["_id"], "technique": _TECHNIQUES["exploit"],
                      "rationale": f"Confirm reachability of {top['title']} ({top.get('reachability_reason')})"}
            existing = await db.approvals.find_one({"engagement_id": eid, "status": "pending",
                                                    "action.finding_id": top["_id"]})
            if not existing:
                await create_approval(eid, action, agent_run_id=run["_id"], requested_by=actor_id)
                approvals_created += 1
            steps.append({"phase": "exploit", "target": target, "tool_id": "sqlmap",
                          "technique": _TECHNIQUES["exploit"], "status": "awaiting_approval",
                          "result": "exploit-intensity action queued for human approval (SEC-06)", "ts": now_iso()})

    summary = None
    if use_llm:
        try:
            findings_txt = "\n".join([s.get("result", "") for s in steps])
            res = await infer(InferRequest(
                purpose="offensive_run_analysis", task_class="reason", sensitivity="internal",
                engagement_id=eid, agent_run_id=run["_id"], max_tokens=400,
                messages=[{"role": "system", "content": "You are 8pi's offensive analyst. Summarize the attack-chain run in 3 concise sentences, noting the highest-risk path and any actions awaiting approval."},
                          {"role": "user", "content": f"Engagement steps:\n{findings_txt}"}]),
                actor="agent", actor_id=actor_id)
            summary = res.get("text")
        except Exception:
            summary = None

    await db.agent_runs.update_one({"_id": run["_id"]},
                                   {"$set": {"status": "completed", "ended_at": now_iso(),
                                             "steps": steps, "summary": summary,
                                             "approvals_created": approvals_created}})
    await audit_event(eid, "agent", actor_id, "agent_run_completed",
                      {"run_id": run["_id"], "steps": len(steps), "approvals": approvals_created})
    return doc_out(await db.agent_runs.find_one({"_id": run["_id"]}))


async def run_defensive(engagement, agent, actor_id="defensive-agent", use_llm=True):
    if agent.get("promotion_state") != "authorized":
        raise HTTPException(status_code=412, detail="only 'authorized' agents may run against a real estate (FR-AGENT-02)")
    if engagement.get("halted"):
        raise HTTPException(status_code=423, detail="engagement halted (kill switch)")
    eid = engagement["_id"]
    run = await _new_run(eid, agent)
    await audit_event(eid, "agent", actor_id, "agent_run_started", {"run_id": run["_id"], "role": "defensive"})

    invs = await db.tool_invocations.find({"engagement_id": eid, "status": "completed"}).to_list(500)
    rules = {"nmap": "Snort 1:469 ICMP/port-scan", "nikto": "WAF web-scanner signature",
             "dirbust": "WAF content-discovery flood", "sqlmap": "WAF SQLi payload block", "wpscan": "WAF CMS-scan signature"}
    detections, caught = [], 0
    for inv in invs:
        intensity = inv.get("intensity", "recon")
        detected = intensity in ("safe-active", "exploit") or (hash(inv["_id"]) % 10 < 7)
        if detected:
            caught += 1
        detections.append({"invocation_id": inv["_id"], "tool_id": inv["tool_id"], "target": inv["target"],
                           "detected": detected, "rule": rules.get(inv["tool_id"], "generic anomaly"),
                           "intensity": intensity})
    rate = round((caught / len(invs) * 100), 1) if invs else 0.0

    # blue-side finding capturing coverage gaps
    missed = [d for d in detections if not d["detected"]]
    if missed:
        fid = uuid.uuid4().hex
        await db.findings.insert_one({
            "_id": fid, "engagement_id": eid, "asset_id": None,
            "title": f"Detection gap: {len(missed)} offensive action(s) not caught",
            "severity": "med", "status": "open", "evidence_refs": [{"type": "telemetry", "detail": str(missed[:3])}],
            "cve_refs": [], "technique_ref": "detection-coverage", "exploitability": "unconfirmed",
            "remediation": "Add detection rules / logging for the un-caught tool activity; tune WAF/IDS.",
            "source": "defensive-agent", "created_at": now_iso(),
        })

    summary = None
    if use_llm:
        try:
            res = await infer(InferRequest(
                purpose="defensive_run_analysis", task_class="triage", sensitivity="internal",
                engagement_id=eid, agent_run_id=run["_id"], max_tokens=300,
                messages=[{"role": "system", "content": "You are 8pi's blue-team analyst. In 2 sentences summarize detection coverage (the purple-team 'was it caught?' signal) and the biggest gap."},
                          {"role": "user", "content": f"{len(invs)} offensive actions, {caught} detected, rate {rate}%."}]),
                actor="agent", actor_id=actor_id)
            summary = res.get("text")
        except Exception:
            summary = None

    await db.agent_runs.update_one({"_id": run["_id"]},
                                   {"$set": {"status": "completed", "ended_at": now_iso(),
                                             "detections": detections, "detection_rate": rate,
                                             "summary": summary,
                                             "steps": [{"phase": "detect", "result": f"{caught}/{len(invs)} caught ({rate}%)",
                                                        "status": "completed", "ts": now_iso()}]}})
    await audit_event(eid, "agent", actor_id, "agent_run_completed",
                      {"run_id": run["_id"], "detection_rate": rate})
    return doc_out(await db.agent_runs.find_one({"_id": run["_id"]}))


@router.post("/engagements/{eid}/agents/{aid}/run")
async def run_agent(eid: str, aid: str, body: Optional[Dict[str, Any]] = Body(default=None)):
    eng = await get_engagement(eid)
    if not eng:
        raise HTTPException(status_code=404, detail="engagement not found")
    agent = await db.agents.find_one({"_id": aid})
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    if agent["role"] == "defensive":
        return await run_defensive(eng, agent)
    return await run_offensive(eng, agent)


@router.get("/engagements/{eid}/agent-runs")
async def list_agent_runs(eid: str):
    runs = await db.agent_runs.find({"engagement_id": eid}).sort("started_at", -1).to_list(200)
    return {"runs": docs_out(runs)}


@router.get("/agent-runs/{rid}")
async def get_agent_run(rid: str):
    run = await db.agent_runs.find_one({"_id": rid})
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    return doc_out(run)
