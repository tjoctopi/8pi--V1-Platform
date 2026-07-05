"""Idempotent dogfood seed: default agents + a fully-worked demo engagement + CVE cache."""
from db import db
from store import get_engagement, get_roe
from orchestration import create_engagement_core, sign_roe_core, activate_core
from vuln_loop import refresh_cve_cache, correlate_engagement
from sensing import run_sensing
from agent_runtime import run_offensive, run_defensive

DEFAULT_AGENTS = [
    {"name": "recon-agent", "role": "recon", "tools": ["nmap"], "max_intensity": "recon",
     "task_class": "summarize", "promotion_state": "authorized"},
    {"name": "offensive-agent", "role": "offensive", "tools": ["nmap", "nikto", "dirbust", "wpscan", "sqlmap"],
     "max_intensity": "exploit", "task_class": "reason", "promotion_state": "authorized"},
    {"name": "defensive-agent", "role": "defensive", "tools": [], "max_intensity": "recon",
     "task_class": "triage", "promotion_state": "authorized"},
    {"name": "web-fuzzer", "role": "offensive", "tools": ["nikto", "dirbust"], "max_intensity": "safe-active",
     "task_class": "reason", "promotion_state": "dev"},
]


async def _seed_agents():
    import uuid
    from store import now_iso
    for a in DEFAULT_AGENTS:
        exists = await db.agents.find_one({"name": a["name"]})
        if exists:
            continue
        await db.agents.insert_one({
            "_id": uuid.uuid4().hex, "name": a["name"], "version": "1.0.0", "role": a["role"],
            "spec": {"model": {"task_class": a["task_class"], "sensitivity": "internal"},
                     "tools": a["tools"], "scope_source": "engagement.roe",
                     "guardrails": {"max_intensity": a["max_intensity"],
                                    "stop_conditions": ["out_of_scope_attempt", "budget_exceeded", "human_halt"]}},
            "owner": "8pi", "promotion_state": a["promotion_state"],
            "last_sandbox_pass": now_iso() if a["promotion_state"] != "dev" else None,
            "created_at": now_iso(),
        })


async def seed_if_empty():
    await refresh_cve_cache()
    await _seed_agents()

    dog = await db.engagements.find_one({"name": "Dogfood — 8pi Internal Estate"})
    if dog:
        # backfill ecosystem-diverse assets on every startup (idempotent)
        await _enrich_ecosystem(dog["_id"])

    if await db.engagements.count_documents({}) > 0:
        return

    seeds = ["10.10.0.0/24", "app.dogfood.8pi.internal", "https://portal.dogfood.8pi.internal"]
    eng = await create_engagement_core("Dogfood — 8pi Internal Estate", seeds, created_by="8pi-operator")
    eid = eng["_id"]
    # widen RoE for the demo and sign it
    await db.roes.update_one({"engagement_id": eid}, {"$set": {
        "scope_allowlist": seeds,
        "scope_denylist": ["10.10.0.1"],
        "allowed_tools": ["nmap", "nikto", "dirbust", "wpscan", "sqlmap"],
        "allowed_techniques": ["T1046", "T1595.003", "T1190", "A03", "A05"],
        "max_intensity": "exploit",
    }})
    await sign_roe_core(eid, "ciso@8pi.internal")
    await activate_core(eid)
    await run_sensing(eid)
    await correlate_engagement(eid)

    off = await db.agents.find_one({"name": "offensive-agent"})
    dfn = await db.agents.find_one({"name": "defensive-agent"})
    eng = await get_engagement(eid)
    if off:
        await run_offensive(eng, off, use_llm=False)
    if dfn:
        await run_defensive(eng, dfn, use_llm=False)

    # ecosystem enrichment for the globe demo (idempotent)
    await _enrich_ecosystem(eid)

    # a second engagement in draft to showcase the RoE-signing workflow
    await create_engagement_core("Design Partner — Acme Corp (Pre-flight)",
                                 ["203.0.113.0/28", "https://acme-staging.example.com"],
                                 created_by="8pi-operator")


async def _enrich_ecosystem(eid):
    """Idempotently attach 7 extra assets to the Dogfood engagement so every
    ecosystem-globe continent (SaaS / Code / Dev / Cloud / Endpoint / Edge / On-Prem)
    populates for the demo. Safe on repeated startup — checks by identifier."""
    from store import now_iso as _iso
    import uuid as _uuid
    extras = [
        {"type": "webapp", "exposure": "external",
         "identifiers": {"url": "https://acme.okta.com", "host": "acme.okta.com"},
         "versions": [{"product": "Okta", "version": "SaaS", "port": 443}], "tags": ["saas"]},
        {"type": "service", "exposure": "internal",
         "identifiers": {"host": "gitlab.dogfood.8pi.internal", "port": 443, "service": "https"},
         "versions": [{"product": "GitLab", "version": "16.4.1", "port": 443}], "tags": ["code", "repo"]},
        {"type": "service", "exposure": "internal",
         "identifiers": {"host": "jenkins.dogfood.8pi.internal", "port": 8080, "service": "http"},
         "versions": [{"product": "Jenkins", "version": "2.414.2", "port": 8080}], "tags": ["cicd", "ci"]},
        {"type": "service", "exposure": "external",
         "identifiers": {"host": "portal.dogfood.8pi.aws.cloudfront.net", "port": 443, "service": "https"},
         "versions": [{"product": "AWS CloudFront", "version": "n/a", "port": 443}], "tags": ["cloud"]},
        {"type": "host", "exposure": "internal",
         "identifiers": {"host": "corp-lap-042.dogfood.8pi.internal", "ip": "10.10.9.42"},
         "versions": [{"product": "Windows 11", "version": "22H2", "port": None}], "tags": ["endpoint", "workstation"]},
        {"type": "service", "exposure": "internal",
         "identifiers": {"host": "cam-edge-07.dogfood.8pi.internal", "port": 554, "service": "rtsp"},
         "versions": [{"product": "Ubiquiti UniFi Camera", "version": "4.62.7", "port": 554}], "tags": ["iot", "edge"]},
        {"type": "service", "exposure": "internal",
         "identifiers": {"host": "dc01.dogfood.8pi.internal", "port": 389, "service": "ldap"},
         "versions": [{"product": "Active Directory", "version": "2019", "port": 389}], "tags": ["onprem", "ad"]},
    ]
    estate_id = None
    eng = await db.engagements.find_one({"_id": eid})
    if eng:
        estate_id = eng.get("estate_id")
    inserted = 0
    for e in extras:
        ident = e["identifiers"]
        host = ident.get("host") or ident.get("url") or ident.get("ip")
        match = {"engagement_id": eid, "$or": [
            {"identifiers.host": host}, {"identifiers.url": host}, {"identifiers.ip": host},
        ]}
        if e["type"] == "service":
            match = {"engagement_id": eid, "identifiers.host": ident.get("host"),
                     "identifiers.port": ident.get("port")}
        if await db.assets.find_one(match):
            continue
        await db.assets.insert_one({
            "_id": _uuid.uuid4().hex, "estate_id": estate_id, "engagement_id": eid,
            "type": e["type"], "identifiers": ident, "versions": e["versions"],
            "first_seen": _iso(), "last_seen": _iso(),
            "attributes": {}, "exposure": e["exposure"], "tags": e["tags"],
        })
        inserted += 1
    return inserted
