# 8π — Execution Plan (the concrete "how")

> Companion to [offensive-depth-plan.md](offensive-depth-plan.md) (why/what) and
> [phases.md](phases.md) (living order). This is the buildable engineering plan: real
> modules mapped onto `src/attack_engine/`, interfaces, data models, tests, the first
> vertical slice, and a hard acceptance gate per phase. Living/dynamic — re-plan as we learn.

## Program shape

**Keep (the spine, don't touch the contracts):** `toolrunner/` (scope, sandbox, rate-limit,
audit), `governance/`, `gateway/` routing + audit, RBAC/`manager.py`, the `api/` shell + SSE,
the React console. Every real action keeps flowing through the Tool Runner boundary.

**Build order (foundation-first):** A Brain → B Proof → C Foothold chain → D Web depth →
E AD/lateral depth → F Adversary emulation → G Scale/eval. A–C are the foundation; D–G get
re-planned once the loop + proof + footholds are real.

**"Extremely next-level" = these are all true, proven live on the range:**
1. The agent **adapts** — it chooses each next action from observed results, not a fixed script.
2. It lands **real footholds** (live session + C2), tracked and kill-switchable, inside signed scope.
3. It **proves impact** on the high-severity classes (RCE/LFI/SSRF/authz), zero false positives.
4. It chains external web → internal → **AD → Domain Admin**, unattended, fully audited.
5. Stated exploit probabilities are **calibrated** (ECE validated), not hand-set.

**Cross-cutting tracks that ride along every phase:** model/cost discipline · a real
integration-test tier that actually lands footholds · safety envelope hardening · metrics.

---

# PHASE A — The Brain (agentic reasoning core)  ← build this first

Everything downstream is scripted tooling until this exists. Four sub-builds, then one slice.
Phase A is also where the **cognition core of the agent fleet** is born — the Strategist, Ideator,
Skeptic, Planner and Reflection agents (the "mind" skeleton). Full fleet design:
[agent-fleet.md](agent-fleet.md); it grows one specialist layer per phase.

## A0 — Model Gateway v2 (prerequisite)
Today `gateway/` is single-shot text-in/text-out; you cannot build an agent loop on it.

**Files:** extend `gateway/types.py`, `gateway/router.py`, `gateway/provider.py`; new `gateway/budget.py`.

- **Tool-calling.** New types in `types.py`: `ToolSpec` (name, description, JSON-schema params),
  `ToolCall` (id, name, args), `ToolResult` (call_id, content). Add roles `assistant`/`tool` +
  helpers. New `ModelGateway.chat(messages, tools=None, tool_choice=...) -> ChatResponse` returning
  either text or `tool_calls`. `provider.py` maps to LiteLLM's `tools=`/`tool_choice=` (works across
  Fireworks/Anthropic; `drop_params=True` already set).
- **Structured output.** `ModelGateway.respond_json(messages, schema: type[BaseModel]) -> BaseModel`
  — force a tool/`response_format`, validate with pydantic, **auto-retry on validation error**
  (same discipline the workflow layer uses). This is how the Planner returns actions safely.
- **Multi-turn + streaming.** Conversation = `list[ChatMessage]`; `stream()` generator for SSE.
- **Budgets.** `budget.py`: `TokenBudget(total, spent())` per engagement; `chat()` raises
  `BudgetExceeded` past the ceiling; wired into the existing hashed-prompt/token audit.
- **Tiering + caching.** Keep tier→model resolution; add prompt-cache markers for the big static
  system prompts (Anthropic `cache_control`).
- **Tests:** extend `MockProvider` to emit deterministic tool-calls / JSON so the whole loop is
  testable offline; unit tests for schema-retry, budget enforcement, tool-call round-trip.

## A1 — World model v2 (structured, probabilistic beliefs)
Today `knowledge/store.py` is a flatish store; beliefs are effectively booleans.

**Files:** new `knowledge/worldmodel.py` + `knowledge/entities.py`; reuse `knowledge/graph_backend.py`;
**activate the already-written but unused `correlate/fusion.py`** (Bayesian log-odds) for belief updates.

- **Entities (pydantic):** `Host`, `Service`, `Endpoint`, `Credential`, `Session`, `Principal`,
  `Trust`, `Hypothesis`, `Finding` — each with `provenance` (source tool, timestamp, engagement),
  `confidence: float`, and typed links. Nothing is a bare bool.
- **Update by fusion, not overwrite:** `WorldModel.observe(evidence)` fuses new evidence into the
  belief via `fusion.py` (independent-signal log-odds), so repeated weak signals accumulate.
- **Query API for the planner:** `open_hypotheses()`, `reachable_assets()`, `owned_set()`,
  `frontier()`, `attack_graph_view()`. Backed by `graph_backend` (NetworkX now, Neo4j in G).
- **Interface designed for externalization** (Postgres/Redis in Phase G) but in-process for A.
- **Tests:** fusion correctness, provenance/confidence, query API, dedup vs the old store.

## A2 — The reasoning loop (Perceive → Plan → Act → Observe → Reflect)
Today `agents/base.py` runs a straight-line `_execute()` per archetype. Replace with a real loop.

**Files:** new `agents/reasoning.py` (the loop) + `agents/actions.py` (data models); keep
`agents/base.py` as the lifecycle/scope wrapper; keep `agents/loader.py` registry.

- **Data models (`actions.py`):** `Action(tool, params, rationale, expected_value)`,
  `Observation(action, raw, evidence)`, `StepDecision(kind: continue|backtrack|escalate|gate|stop)`,
  `LoopState(step, budget, history)`.
- **Loop components (`reasoning.py`):**
  - `ContextAssembler` (**Perceive**) — retrieve the relevant world-model slice into context
    (not dump-everything); include recent history + retrieved TTP playbooks.
  - `Planner` (**Plan**) — `gateway.respond_json(..., schema=list[Action])` → ranked candidate
    actions with rationale + EV. Tradecraft system prompt (few-shot exemplars, chain-of-thought).
  - `Actor` (**Act**) — map the chosen `Action` to a **Tool Runner** tool call (scope/RoE enforced
    at the boundary, unchanged). High-impact actions raise a human gate here.
  - `Observer` (**Observe**) — deterministic parse of tool output → `Evidence` → `WorldModel.observe`.
  - `Reflector` (**Reflect**) — LLM + heuristics: progress assessment, stuck/loop detection,
    self-critique, and the `StepDecision`. Never marks a finding "confirmed" (that's the oracle's job).
  - `Memory` — episodic (action→result) + retrieval for the next Perceive.
- **Loop control:** max steps, per-step budget check, no-progress detection, stop conditions.
  Propose-vs-confirm sacred: the loop proposes; oracles confirm.
- **Tests:** loop control (stuck/backtrack/stop), planner schema round-trip against MockProvider,
  observer→world-model update, gate-on-high-impact, budget stop.

## A3 — Objective-driven orchestrator (replaces the fixed 8-phase DAG)
Today `orchestrator/orchestrator.py` is an `if/elif` phase switch; `plan.py` is a static DAG.

**Files:** new `orchestrator/controller.py` + `schemas/objective.py`; keep the old orchestrator behind
a `AE_ORCHESTRATOR=legacy|objective` flag during migration (don't rip it out until the new one proves out).

- **`Objective` (`schemas/objective.py`):** typed goal + a satisfaction predicate over the world model
  — e.g. `ReachPrivilege(host, priv)`, `ReadCanary(path)`, `DomainAdmin(domain)`.
- **`ObjectiveController`:** loop — query world model → ask a Planner for the highest-EV next action
  toward the objective → dispatch to the right specialist agent → observe → update graph → repeat
  until objective satisfied / dead-end / gate / budget.
- **Action selection:** `utility = success_prob × progress_toward_objective ÷ cost` over the attack
  graph; start greedy/EV, design the seam for MCTS lookahead later.
- **Tests:** controller reaches a toy objective on a mocked world model; dead-end + budget handling;
  legacy-flag parity.

## A4 — First specialist on the loop + the vertical slice (the gate)
Migrate **Recon** first (smallest toolbelt, clearest adaptivity story). Web follows the same pattern.

- **Recon specialist** driven by `ReasoningLoop` with a real toolbelt (nmap, httpx, ffuf via the
  existing wrappers) and a tradecraft system prompt; emits structured hypotheses into the world model.
- **API:** expose as a background job with **SSE reasoning narrative** (reuse the PR-#4 async job + SSE).
- **Console:** render the live "why" per step (the reasoning narrative) in the existing UI.
- **Live range proof (the acceptance gate):** run against Juice Shop / DVWA / Metasploitable and
  show the agent **adapting** — e.g. discovers port 3000, *decides* to httpx it, *then decides*
  content discovery based on what it saw. Demonstrable adaptivity = Phase A done.
- **Tests:** unit (all above) + an **integration smoke** that runs the loop against the range
  (first entry in the new integration tier).

**Phase A definition of done:** pytest/ruff/mypy green · new tests · live range proof of adaptive
behavior · SSE narrative visible in the console · legacy orchestrator still selectable behind the flag.

---

# PHASE B — Proof foundation (make "confirm" real)

**Files:** new `verify/oob/` (client + token minting), new oracles in `verify/oracles/`, wire the dead
`correlate/nvd.py`, fit the real `correlate/calibrate.py`, activate `correlate/fusion.py` in verify.

- **OOB interaction server** — Burp-Collaborator-style DNS+HTTP callback capture with a unique token
  per probe; correlate hits back to the probe. Dev-local now; deployed service in G. *Critical infra —
  blind vulns can't be proven without it.*
- **Impact oracles** (register in `verify/oracles/__init__.py`): `rce_command_output` (canary echo),
  `lfi_file_read` (known file), `ssrf_oob`, `xxe_oob`, `deserialization_oob`, `authz_bypass`
  (cross-identity access), and a **baseline-anchored SQLi** oracle (fixes the current TRUE≠FALSE
  false-positive hole by comparing against a normal-request control + optional data-extraction proof).
  Extend `verify/verifier.py` so server-side classes can actually reach VERIFIED/CONFIRMED.
- **Real CVE/KEV/EPSS pipeline** — activate `correlate/nvd.py` `build_feed` (currently dead code) as a
  cached ingest job; add **EPSS** + exploit-maturity (exploit-DB / nuclei / Metasploit presence);
  retire the 3-record `cve_seed.json` toy feed.
- **Real calibration** — build a labeled dataset from range runs (`evals/data/`), call
  `Calibrator.fit()`, validate ECE/Brier on held-out labels, wire the fitted calibrator into
  `ExploitabilityScorer` + `Verifier` (at `engine.py` construction). Turn on `fusion.py` in the pipeline.
- **Gate:** a server-side **RCE on the range reaches CONFIRMED** with impact evidence and a calibrated
  probability that validates on held-out labels.

---

# PHASE C — Foothold chain (real footholds + C2)

**Files:** new `exploit/msf_rpc.py`; rework `exploit/metasploit_exploit.py`; real backend in
`c2/backend.py`; live handles in `c2/session.py`; governed ops in `c2/postex.py`.

- **Persistent msfrpcd** — deploy `msfrpcd` as a service; `msf_rpc.py` is a `pymetasploit3` client
  replacing the one-shot `--rm msfconsole`. Exploit selection driven by the CVE/service correlation.
- **Real session lifecycle** — `MetasploitExploitModule.confirm()` calls
  `SessionManager.open_session()` with a **live RPC handle**; `c2/session.py` holds real sessions;
  the kill-switch (`close_all`) tears down real sessions. *Closes the dead O2→O3 seam.*
- **Real C2** — implement a real `C2Backend` behind the existing interface: **Sliver** via its
  gRPC/operator API (recommended primary), Meterpreter-over-msfrpc secondary. Beacon tasking, output
  collection, SOCKS pivot, file ops — all governed.
- **Post-ex + proof-of-impact** — `PostExOperator` runs over the real backend (gated for high-impact);
  capture bounded evidence (`whoami`/`hostname`/`uname`, a **scoped canary** read) → promote to
  CONFIRMED-owned. Never exfil real data.
- **Governance hardening rides along:** egress control on sandbox/C2 (implants reach only authorized
  targets + the listener), kill-switch teardown of live beacons, evidence capture (command logs,
  request/response) hash-chained into the audit, captured-credential vaulting.
- **Gate:** exploit → live session → `whoami` on the range, tracked and kill-switchable.

---

# PHASE D — Web depth (XBOW-class)  *(re-planned after A–C land)*

- **Web specialist on the reasoning loop:** app-understanding (crawl → model of endpoints / auth /
  roles / object references / data flows), LLM context-aware payload synthesis, a chaining engine
  (open-redirect → SSRF → cloud-metadata → creds → foothold, tracked as a world-model path).
- **Modern classes:** IDOR/broken-authz, SSRF→metadata, SSTI, deserialization, XXE, all SQLi
  dialects, command injection, JWT/OAuth flaws, GraphQL abuse, prototype pollution, request smuggling,
  cache poisoning, business-logic, race conditions. Every candidate → a Phase-B impact oracle.
- **Gate:** an autonomous chain lands a **proven web foothold** on the range.

---

# PHASE E — Identity / AD / lateral depth (NodeZero-class)  *(re-planned after A–C)*

- **Native tooling** (real): impacket, certipy, ldap3, kerbrute, netexec/crackmapexec — wrapped as
  tools *and* driven over live sessions/SOCKS.
- **Full abuse graph (real edges from collected data):** Kerberoast / AS-REP, **ADCS ESC1-8**,
  delegation (unconstrained/constrained/RBCD), DCSync, ACL abuse, GPO abuse, domain trusts.
- **Credential lifecycle:** capture → crack (hashcat) → reuse (PtH/OverPtH/PtT) → escalate.
- **Real lateral execution:** SOCKS pivot via C2, remote exec (wmiexec/psexec/winrm/smbexec),
  establish sessions on new hosts, **frontier expansion** in the campaign runner (re-plan from each
  new vantage). **Grounded path planning:** feed the *correct* existing Dijkstra real edges (replace
  the fabricated constant-cost synthetic edges).
- **Needs a minimal AD-forest range** (bring up early; full version in G).
- **Gate:** foothold → **Domain Admin** on the AD-forest range.

---

# PHASE F — Full adversary emulation  *(re-planned after A–E)*

- Full autonomous campaign across the whole chain; **adversary profiles** bias the policy (which
  TTPs, how loud, MITRE ATT&CK actor emulation); **T2/T3** autonomy; **gated evasion testing**
  (a measured defensive-testing capability behind explicit authorization + gates — never general malware).
- **Gate:** external → Domain Admin, unattended, fully audited.

---

# PHASE G — Scale & continuous eval  *(re-planned after A–F)*

- **Externalize** world model/state to Postgres + Redis (survive restart, multi-node, kill sticky
  sessions); **Neo4j** attack graph.
- **Persistent services:** C2, msfrpcd, OOB collaborator, a **tool-executor pool** for parallel scans.
- **Benchmark range** (multi-host AD forest, vulnerable web apps, known-CVE boxes, cloud-metadata
  scenario) + **continuous calibration/regression** (integration tier that actually lands footholds).
- **Gate:** multi-node, benchmarked, **FP ≈ 0**.

---

## Cross-cutting tracks (every phase)

- **Model & cost.** Per-engagement token/cost budgets; frontier model for planning, cheap/local model
  for bulk classification; prompt caching. Track $/engagement as a first-class metric.
- **Testing & range.** New **integration tier** that runs against the live range and actually lands
  footholds — fixes the current ~0% real-offensive-I/O problem. Unit suite stays zero-external-services.
- **Safety envelope.** Strengthens with each real-weapon phase (C/E/F): egress control, kill-switch
  teardown, evidence capture, data minimization (canary not data), credential vaulting, HTTP human gates.
- **Metrics that define "top-tier."** Kill-chain depth reached · confirmed/proposed ratio ·
  **false-positive rate → 0** · time-to-foothold · MITRE ATT&CK coverage · calibration ECE/Brier.
- **Observability.** Agent-decision tracing (the "why" behind each action) surfaced over SSE to the console.

## Sequencing & rough sizing (indicative, in "slices" not calendar)

| Phase | Slices (rough) | Unblocks |
|---|---|---|
| A Brain | A0 gateway, A1 world model, A2 loop, A3 controller, A4 recon slice | everything |
| B Proof | OOB, impact oracles, CVE/EPSS, calibration | trustworthy "confirmed" |
| C Foothold | msfrpcd, sessions, C2, post-ex, proof-of-impact | real footholds; D/E |
| D Web | web-specialist loop, chaining | external access |
| E AD/lateral | native tooling, abuse graph, cred lifecycle, lateral exec | Domain Admin |
| F Emulation | campaign, profiles, T2/T3, evasion | the vision |
| G Scale/eval | externalized state, executor pool, benchmark | production-grade |

Do one slice at a time (engine → API → console), tested + proven live, merged to `dev`. Re-plan the
order when reality warrants — this is a living plan.

## Risks & honest constraints
- **Cost:** a real reasoning loop burns tokens — budgets/tiering/caching are first-class from A0.
- **Reliability:** real exploitation is flaky; the loop must expect failure and never report a failed
  action as success (honesty rule). Retry intelligently, backtrack, gate.
- **Legal/ethical:** real weaponization runs only inside a signed, unexpired, authorized scope; C2 and
  evasion are defensive-testing tools behind explicit gates. That line is the product boundary; we hold it.
- **Effort:** multi-phase program — but every phase is a shippable, testable increase in real capability,
  not a big-bang rewrite.
