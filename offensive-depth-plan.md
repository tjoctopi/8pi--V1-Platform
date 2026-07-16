# 8π — Offensive Depth Blueprint (next-level, not starter)

> **Purpose.** Take 8π from a well-engineered *scan-and-signal* harness to a genuinely
> top-tier autonomous offensive platform — full adversary emulation (external web →
> internal network → AD → domain compromise), landing **real footholds** inside a
> signed scope, with an AI that **reasons like a hacker** instead of running a fixed
> script. Build on the parts that are genuinely strong; rebuild the parts that are thin;
> add deep analysis layers at every stage.
>
> **Non-negotiables carried forward:** propose (LLM) vs confirm (deterministic code) ·
> scope/rate/RoE enforced at the Tool Runner boundary, never in an agent · roles not
> tool-copies · model-agnostic (BYOM) · every real action wrapped in scope + sandbox +
> audit + gate + kill-switch. Real weapons make these *stronger*, not optional.

---

## 0. Honest baseline (what we actually have today)

**Genuinely strong — keep and build on:**
- Governance spine: radix-trie CIDR scope, hash-chained audit, per-(tool,target) token-bucket
  rate limits, human gates, licensed-tool gating. Production-quality.
- Real hardened Docker sandbox (`--read-only`, `cap-drop ALL`, no-new-privileges, pids-limit,
  scoped network, optional gVisor). Actually spawns containers.
- Config-driven model routing (BYOM), full call audit (hashed prompts, token usage).
- Correct algorithms: Dijkstra pathing, confusion-matrix / Brier / ECE metric math, version-
  interval CVE matching, dedup, RBAC/multi-tenant isolation.

**Thin / facade — rebuild with depth:**
- **No AI brain.** LLM used in 2 cosmetic spots; no ReAct/tool-calling/planning/reflection.
  Orchestrator is a fixed 8-phase `if/elif` script. Not actually agentic.
- **No real exploit→foothold→C2 chain.** Exploit = one-shot `msfconsole` in a `--rm`
  container; a "session" is a stdout regex that dies instantly and is never registered.
  C2 is an in-memory mock; no implant; post-ex hits the mock.
- **"Confirm" proves only low-severity signals.** 4 web oracles (XSS/redirect/boolean-SQLi/
  version). Server-side RCE class can *never* reach CONFIRMED. No oracle proves impact.
- **"Calibrated exploitability" never calibrated** (`.fit()` never called); CVE feed is a
  3-record toy JSON; real NVD/KEV ingest exists but is dead code; EPSS/exploit-maturity absent.
- **AD/lateral = labels over booleans.** No LDAP/Kerberos/SMB code of its own; no ADCS/
  delegation/trusts; lateral movement is `PLANNED`. Defense "detection" greps its own audit log.
- **Tests prove ~0% real offensive I/O** by design (noop sandbox + mock model).

**Design consequence:** the spine is a chassis. We are building the engine, drivetrain, and
driver — the AI reasoning loop, the real exploitation/C2 chain, deep confirmation, and real
identity/AD/lateral capability — on top of it.

---

## 1. Design philosophy — "think like a hacker," then design

A real elite operator does **not** run a fixed checklist. They build a mental model of the
target, form hypotheses, test the cheapest highest-value one, read the result, update their
beliefs, and chain weak signals into full compromise — opportunistically, toward an objective.
Every layer below is designed around that loop, not around a phase list.

**The five design tenets that shape everything:**

1. **A world model is the source of truth, not a phase list.** Beliefs about the target
   (assets, services, creds, sessions, trusts, hypotheses) are structured, probabilistic, and
   provenance-tracked. The next action is *derived* from the world model + objective, never
   hardcoded.
2. **Everything is evidence with confidence.** No boolean "vulnerable." Each observation has a
   source, a confidence, and a decay. Beliefs update by fusion, not overwrite.
3. **Propose vs confirm stays sacred.** The LLM proposes *what to try and why*; deterministic
   oracles decide *whether it worked*. We never promote an LLM claim to truth.
4. **Depth per finding, not breadth of maybes.** For each signal: understand the *why*, prove
   *impact*, then *chain* it. One proven full-compromise path beats a thousand "info" findings.
5. **Safety scales with lethality.** The moment we land real shells, scope/audit/gate/kill-switch
   get *stronger* (egress control, evidence capture, data minimization, credential vaulting).

**"Analyze every part deeply" in practice:** every capability domain below gets (a) a hacker-
tradecraft model of what a human expert actually does, (b) an AI-reasoning design for how the
agent decides, (c) a real-tooling design for how it acts, (d) a deterministic proof design for
how we confirm, and (e) a robustness design (failure handling, confidence, provenance, tests).

---

## 2. THE BRAIN — Agentic reasoning core (highest priority; nothing deep works without it)

This is the #1 gap. Today the "agents" are deterministic tool pipelines. We rebuild the brain.

### 2.1 Model Gateway v2 (prerequisite for the whole brain)
The current gateway is single-shot text-in/text-out with no tool-calling or structured output —
you literally *cannot* build an agent loop on it. Add:
- **Tool/function calling** — the model emits a validated tool call, not prose we regex.
- **Structured output** — JSON-schema / response_format, validated at the boundary, auto-retry
  on mismatch (mirror the pattern the workflow layer already uses).
- **Multi-turn** assistant/tool roles + conversation state; **streaming** for live SSE narrative.
- **Budgets & tiering** — per-engagement token/cost ceilings; frontier model for planning,
  local/cheap model for bulk classification; **prompt caching** for the big static system prompts.
- Keep BYOM + full audit; add per-decision tracing ("why did the agent choose this").

### 2.2 The reasoning loop (Perceive → Hypothesize → Act → Observe → Reflect)
Replace `_execute()` straight-line scripts with a real loop per agent:
- **Perceive** — assemble relevant world-model slice into context (retrieval, not dump-everything).
- **Plan/Hypothesize** — LLM proposes ranked candidate actions with expected value + rationale.
- **Act** — selected action becomes a *tool call* through the Tool Runner (scope-enforced).
- **Observe** — deterministic parse of tool output → structured evidence.
- **Reflect/Critique** — LLM (and heuristics) judge progress, detect stuck/loops, update beliefs,
  decide continue/backtrack/escalate/gate. Self-critique to cut false confidence.
- **Memory** — episodic (what I tried + result) + semantic (learned target facts) + procedural
  (TTP playbooks retrieved by relevance).

### 2.3 World model / blackboard v2
Upgrade the flat knowledge store to a structured, probabilistic belief state:
- Entities: Host, Service, Endpoint, Credential, Session, Identity/Principal, Trust, Hypothesis,
  Finding — each with provenance, confidence, timestamps, and links.
- Backed by the attack/privilege graph (Neo4j in prod) so planning queries real relationships.
- Shared across all specialist agents; concurrency-safe; externalized (Postgres/Redis) so state
  survives restart and scales past one node.

### 2.4 Objective-driven orchestrator (replaces the fixed 8-phase DAG)
- Input: a **named objective** ("Domain Admin on corp.local", "read the crown-jewel DB").
- Loop: query world model → planner proposes highest-EV next action toward objective → dispatch
  to the right specialist → observe → update graph → repeat until objective, dead-end, or gate.
- Action selection: utility/EV over the attack graph (cost × success-prob × progress-toward-goal);
  optionally MCTS-style lookahead for multi-step chains. Grounded in *real* confirmed edges.
- Adversary profiles bias the policy (which TTPs, how loud, MITRE ATT&CK emulation of a named actor).

### 2.5 Specialist agents as reasoning skills (roles, not scripts)
Recon · Web · Exploit · Identity/AD · Lateral · Post-Ex · Remediation — each an LLM-driven agent
with a toolbelt, a tradecraft system prompt, few-shot exemplars, and structured outputs. New TTPs
= a new tool wrapper the agent can call, not a cloned agent (rule #3 preserved).

**Deliverable slice:** gateway v2 → world-model v2 → one specialist (Recon or Web) on the real
loop → objective orchestrator driving it. Prove the loop end-to-end before scaling to all agents.

---

## 3. RECON & attack-surface intelligence (deep)

**Hacker model:** recon is 80% of the win. Passive first (no touch), then active, then synthesize
into a target model and a *ranked hypothesis list* — "this smells like a Rails app with an exposed
admin and an old jQuery; likely IDOR + a known CVE."

- **Passive/OSINT:** cert transparency, subdomain enum (subfinder/amass), ASN/BGP, DNS, tech
  fingerprinting, breach/credential OSINT, git/secret leaks, cloud-asset discovery (S3/blob/buckets).
- **Active:** masscan→nmap depth, service/version, content discovery (ffuf/katana), **JS analysis**
  for hidden endpoints/API routes/secrets, API-spec harvest (OpenAPI/GraphQL introspection).
- **AI synthesis:** LLM turns raw recon into a structured target model + prioritized attack
  hypotheses with rationale, feeding the orchestrator's action selection.
- **Continuous (T3):** attack-surface management — diff over time, alert on new exposure.
- **Robustness:** dedup, per-source provenance, confidence, rate-limit headroom for probe storms.

---

## 4. WEB / APP exploitation (XBOW-class depth)

**Hacker model:** understand the app as a system (routes, params, auth model, data flow, trust
boundaries), form vuln hypotheses, synthesize *context-aware* payloads, iterate on responses,
and chain low-severity into high. Today's web agent is deterministic tool-chaining + a static
injection wordlist — we replace the reasoning.

- **App understanding:** crawl + LLM builds a model of endpoints, auth/session model, roles,
  object references, and data flows.
- **LLM-driven vuln reasoning + payload synthesis** for modern classes: IDOR/broken-authz,
  SSRF (→ cloud metadata → creds), SSTI, deserialization, XXE, SQLi (all dialects), command
  injection, JWT/OAuth flaws, GraphQL abuse, prototype pollution, request smuggling, cache
  poisoning, business-logic flaws, race conditions.
- **Auth handling:** real login flows, session/token management, multi-step, privilege contexts
  (test the same action as user A vs user B for authz bugs).
- **Chaining engine:** open-redirect → SSRF → metadata → cloud creds → foothold, tracked as a
  path in the world model.
- **Proof:** every candidate goes to a real impact oracle (Part 6), never "reflected → done."

---

## 5. EXPLOITATION → FOOTHOLD → C2 (the biggest missing chain; make it real)

**Hacker model:** an exploit is worthless unless it yields a *controllable, persistent* session
you can operate from. Today the chain is broken at every joint.

- **Persistent exploit execution:** stand up **Metasploit RPC (msfrpcd)** as a long-lived service
  (pymetasploit3), not a one-shot `--rm` msfconsole. Plus standalone/custom modules and exploit-DB/
  nuclei-driven exploitation. Dynamic exploit *selection* driven by the CVE/service correlation.
- **Real session lifecycle:** a confirmed exploit calls `SessionManager.open_session()` with a
  **live handle** to a surviving handler. Sessions are tracked, scope-bound, evidence-logged, and
  torn down by the kill-switch. This closes the dead O2→O3 seam.
- **Real C2:** integrate a real framework behind the existing `C2Backend` interface — **Sliver**
  (gRPC API, OSS, modern) is the recommended primary; Meterpreter via msfrpc as secondary. Beacon/
  session tasking, output collection, SOCKS pivoting, file ops — all governed.
- **Post-exploitation:** real host/situational enumeration, credential harvesting, and privilege
  discovery over the live session (governed, gated for high-impact).
- **Proof-of-impact → CONFIRMED-owned:** capture bounded evidence (whoami/hostname/uname, a scoped
  **canary** file read) — never exfil real data.
- **Payload generation/staging** and, since scope includes evasion testing, controlled AV/EDR-
  evasion *as a measured test capability* inside the safety envelope (see Part 7 for the guardrails).

---

## 6. IDENTITY / AD / LATERAL MOVEMENT (NodeZero-class depth)

**Hacker model:** internal compromise is an identity game — collect the graph, find the cheapest
path to a Tier-0 asset, harvest/crack/reuse credentials, and walk it. Today it's a pretty diagram
over fabricated constant-cost edges with zero protocol code.

- **Native protocol tooling (real):** impacket, ldap3, certipy, bloodhound-python, kerbrute,
  crackmapexec/nxc — wrapped as tools *and* driven over live sessions/SOCKS.
- **Full AD abuse graph (real edges from collected data):** Kerberoast / AS-REP roast, **ADCS
  ESC1–8**, delegation (unconstrained / constrained / RBCD), DCSync, ACL abuse, GPO abuse,
  domain trusts / cross-domain, session hunting.
- **Credential lifecycle:** capture → **crack (hashcat)** → reuse (PtH / OverPtH / PtT) → escalate,
  tracked as credential entities with confidence + scope.
- **Real lateral execution:** SOCKS pivot via C2, remote exec (wmiexec/psexec/winrm/smbexec),
  establish sessions on new hosts, and **frontier expansion** in the campaign runner (owned-set
  grows; re-plan from each new vantage).
- **Grounded attack-path planning:** replace the constant-cost synthetic edges with edges derived
  from *actually collected* relationships and *confirmed* capabilities; costs from real exploit
  probability + reachability. The Dijkstra/graph code is already correct — feed it real data.

---

## 7. CONFIRM ENGINE v2 — deep, zero-false-positive proof (make the core promise true)

**Hacker model:** proof is impact, not a signal. "The marker reflected" is not XSS; "I read
/etc/passwd" is LFI; "my OOB server got a hit" is blind SSRF. Today no oracle proves impact and
the whole server-side class can't be confirmed.

- **Impact oracles for every high-severity class:** RCE (deterministic command-output canary),
  LFI/path-traversal (read a known file), SSRF/XXE/blind-SQLi/deserialization (**out-of-band
  interaction**), auth-bypass (access a protected resource across identities), SQLi (baseline-
  anchored + data-extraction/error proof — fixes the current TRUE≠FALSE false-positive hole).
- **OOB interaction server (build it):** a Burp-Collaborator-style DNS/HTTP callback service —
  critical infrastructure for proving *blind* vulnerabilities. Nothing top-tier works without it.
- **Real CVE/KEV/EPSS pipeline:** wire the existing (dead) NVD/KEV ingest live; add **EPSS** and
  **exploit-maturity** (exploit-DB/Metasploit/nuclei presence). Replace the 3-record toy feed.
- **Re-test on confirm:** CVE confirmation should re-touch the host (version + behavioral check),
  not just a version-in-interval match on a possibly-stale banner.
- **Real calibration:** build a labeled dataset from range + historical runs, **fit** the
  calibrator (Platt/isotonic), validate ECE/Brier, and activate the unused Bayesian fusion module
  so "0.9 means right 90% of the time" is empirically *true*, not just documented.

---

## 8. GOVERNANCE & SAFETY at real-weapon lethality (harden the spine)

Landing real shells raises the stakes — the envelope must get stronger, not looser.

- **Scope v2 / RoE:** time windows & blackout periods, destructive-action classes (default deny),
  data-handling rules, and **egress control** on the sandbox and C2 (implants can only reach
  authorized targets + the C2 listener).
- **Human gates over HTTP (async responder):** high-impact actions (real exploit, lateral into
  prod, anything destructive, evasion tests) block on a real approve/deny from the console.
- **Kill-switch that means it:** tears down live sessions *and* C2 beacons, not just refuses new calls.
- **Evidence capture:** command logs, request/response, screenshots, pcaps — hash-chained into the
  audit log as court-grade proof every action was in-bounds.
- **Data minimization & credential vaulting:** proof reads a canary, never real data; captured
  creds/secrets are encrypted, scoped, access-controlled, and auto-purged at engagement end.
- **Evasion testing framing:** treated as a *measured defensive-testing* capability inside signed
  scope with explicit authorization + gating — never a general-purpose "make malware undetectable" tool.

---

## 9. STATE, SCALE & INFRASTRUCTURE

- Externalize world model/blackboard to **Postgres + Redis** (survive restart, multi-node, kill
  sticky-session dependence). Neo4j for the real attack graph.
- **Persistent C2 server** and **msfrpcd** as deployed services (not ephemeral).
- **Tool-executor pool** for parallel sandboxed tool runs (recon/scan storms without blocking).
- **Observability:** agent-decision tracing (the "why" behind every action), token/cost dashboards,
  per-engagement metrics, live SSE narrative of the campaign.

---

## 10. EVALUATION — how we *know* it's top-tier (not vibes)

Today: correct metric math over a 3-sample toy dataset, fed by hand; ~0% real offensive I/O in tests.

- **Real range + benchmark suite:** multi-host AD forest, vulnerable web apps, known-CVE boxes,
  CTF-style targets, a cloud-metadata scenario. Each *capability* has a range target that proves it
  end-to-end (an **integration test tier** that actually lands the foothold — fixes the 0% problem).
- **Metrics that matter:** kill-chain depth reached, confirmed/proposed ratio, **false-positive
  rate (must trend to ~0)**, time-to-foothold, MITRE ATT&CK coverage, calibration ECE/Brier.
- **Regression + adversarial evals:** every merged capability keeps its range proof green; LLM-judge
  scores reasoning quality; "red-team the red-team" scenarios stress the safety envelope.
- **Feedback loop:** failed exploits/paths feed prompt/tool/playbook improvements.

---

## 11. SEQUENCING — foundation-first, one vertical slice at a time

Each item is a vertical slice (engine → API → console), tested (pytest/ruff/mypy green + a live
range proof), merged to `dev` before the next. Foundations first because depth downstream is
impossible without them.

- **Phase A — Brain foundation.** Gateway v2 (tool-calling/structured/streaming/budgets) →
  world-model v2 → the reasoning loop on one specialist → objective-driven orchestrator. *Gate:
  the agent adapts its next action from observed results on the live range.*
- **Phase B — Proof foundation.** OOB interaction server → impact oracles for the high-severity
  classes → real CVE/KEV/EPSS pipeline → fitted calibration. *Gate: a server-side RCE reaches
  CONFIRMED with impact evidence and a truthful probability.*
- **Phase C — Foothold chain.** Persistent msfrpcd → real session lifecycle → real C2 (Sliver) →
  governed post-ex → proof-of-impact. *Gate: exploit → live session → whoami, tracked & kill-switchable.*
- **Phase D — Web depth.** LLM web-exploitation agent (app understanding, payload synthesis,
  chaining) over modern vuln classes. *Gate: autonomous chain lands a proven web foothold.*
- **Phase E — Identity/AD/lateral depth.** Native AD tooling → full abuse graph → credential
  lifecycle → real lateral execution → grounded path planning. *Gate: autonomous foothold →
  Domain Admin on the AD-forest range.*
- **Phase F — Adversary emulation.** Full autonomous campaign across the whole chain, adversary
  profiles, T2/T3 autonomy, evasion testing (gated). *Gate: end-to-end external→DA, unattended, audited.*
- **Phase G — Scale & continuous eval.** Externalized state, executor pool, benchmark suite,
  continuous calibration/regression. *Gate: multi-node, benchmarked, FP≈0.*

Governance hardening (Part 8) rides along with every real-weapon phase (C, E, F), not as a separate tail.

---

## 12. Risks & honest constraints

- **Cost:** a real reasoning loop burns tokens. Budgets, tiering, caching, and cheap-model
  offload are first-class, not afterthoughts.
- **Reliability:** real exploitation is flaky; the loop must expect failure, retry intelligently,
  and never present a failed action as success (honesty rule).
- **Legal/ethical:** real weaponization is only ever run inside a signed, unexpired, authorized
  scope. Evasion/C2 capabilities are defensive-testing tools behind explicit gates — this is the
  line between a red-team platform and malware, and we hold it.
- **Effort:** this is a multi-phase, multi-month program. The value is that each phase is a
  shippable, testable increase in real capability — no big-bang rewrite.
