# 8pi — Agentic Cybersecurity Platform (v1)

## Original Problem Statement
"use the spec file to build the 8pi platform v1" — build v1 from `8pi_Platform_v1_Spec.md`, an agentic
cybersecurity (purple-team) platform. Scope = spec Phase 0 + Phase 1 (thin vertical slice through a
customer-gradeable purple-team workflow). Every P0 `MUST` in the spec is a build blocker.

## User Decisions (kickoff)
- Breadth-first full end-to-end slice.
- Security tools = **SIMULATED / MOCK adapters** (deterministic; no real network scanning).
- Model Gateway hosted route = **hosted LLM API key** (Claude Sonnet 4.6). Local route simulated.
- **No auth** in v1 (single operator). RBAC roles exist via a top-bar role switcher (operator/approver/viewer).
- Design = clean modern SaaS dashboard → delivered as a tactical dark "control room" console.

## Stack (deviation from spec §1.2 defaults — recorded per spec rules)
- Backend: **FastAPI + MongoDB (Motor)** instead of Postgres/Neo4j. UUID string `_id`s.
- Frontend: **React (CRA) + Tailwind**, @phosphor-icons, custom SVG threat map.
- Isolation/containers (NFR-ISO-01) are represented at the model level (per-engagement scope + audit),
  not real per-engagement network namespaces (sandbox environment limitation). Documented.

## Architecture — spec components → backend modules (all routes under /api)
- C-07 Orchestration & Audit → `orchestration.py` (+ `audit.py` hash chain, `store.py` helpers)
- C-02 Model Gateway (BYOM)  → `model_gateway.py` (hosted Claude + local sim + openmythos 501 stub)
- C-03 Tool Service          → `tool_service.py` (+ `sim_tools.py`, `scope.py` scope/intensity)
- C-01 Sensing               → `sensing.py`
- C-08 Threat-Model Engine   → `threat_model.py`
- C-09 Vuln & Patch Loop     → `vuln_loop.py` (+ `cve_data.py` CVE/KEV cache)
- C-04/05/06 Agent runtime + offensive/defensive → `agent_runtime.py`
- C-10 Reporting             → `reporting.py` (JSON + HTML + PDF)
- Seed                       → `seed.py` (idempotent dogfood engagement + agents + CVE cache)
- Entry                      → `server.py`

## Frontend
- `src/App.js` routes: `/` Dashboard, `/engagements/:id` detail (9 tabs), `/agents`, `/model-gateway`.
- Tabs: Overview, RoE, Assets, Threat Map, Console, Findings, Vuln Loop, Audit, Report.
- Kill switch in engagement header (confirm-type "HALT"). Approvals in Console (require approver role).

## Implemented & Verified (2026-06 / build date)
- Engagement lifecycle + signed immutable RoE + activation gate (SEC-01, FR-ORCH-01).
- Tamper-evident hash-chained audit + verify endpoint (SEC-04, verified valid on dogfood).
- Model Gateway: real Claude hosted route working; sensitive/airgapped pinned local (SEC-05) + redaction; openmythos 501.
- Tool Service: scope-checked sim tools; out-of-scope refused (SEC-02); licensed tools 451 (FR-TOOL-07).
- Sensing → 28 assets on dogfood; Threat map (28 nodes/22 edges) ranked by exploitable exposure.
- Vuln loop: 41 findings, CVE/KEV correlation, exploitable flag, remediate → re-test → close.
- Agents: sandbox promotion gate; offensive chain creates approval-gated exploit steps (4 pending); defensive detection rate.
- Approval gate approve/deny (approver RBAC); Kill switch halts + cancels approvals (SEC-10).
- Reporting JSON + HTML + PDF (200s), reproducible from audit.

## Iteration 2 — Depth features (added, tested 100% pass)
- **Attack-path engine** (`attack_path.py`): derives entry-point → pivot → crown-jewel paths from the asset
  graph + exploitable findings; classifies roles (datastores/web ports); GET `/attack-path` returns paths + globe points/arcs.
- **Real-time AI attack path**: GET `/attack-path/stream` (SSE) streams a live Claude narrative that chains every
  finding/CVE into the most likely route to crown jewels (client-side typewriter reveal). Records a DM-08 model call.
- **3D globe attack-surface**: `react-globe.gl` view mapping the target ecosystem — entry points around the globe,
  animated attack arcs flowing into pulsing crown-jewel rings (WebGL error-boundary + fallback).
- **Asset drill-down**: GET `/engagements/{id}/assets/{aid}` → asset + findings + parent/children + tool activity; modal in Assets tab.
- **Real-time engagement mini-logs**: Dashboard cards for active/paused engagements poll the audit log every 4s (live terminal).

## Iteration 3 — Deployment readiness (100% pass, 24/24 backend)
- **Liveness endpoints**: `/api/health` (dep-free) + `/api/readiness` (mongo ping).
- **Global error boundary + 404 route** (`AppErrorBoundary`, `NotFound`), inline SVG favicon.
- **WebGL dispose cleanup fix** (captured null ref → zero context-lost errors on rapid tab switching).

## Iteration 4 — Ecosystem Globe redesign (Option C, 100% pass, 26/26 backend)
- **7-way ecosystem classifier** in `attack_path.py`: every asset → one of `endpoint | saas | cloud | dev | code | onprem | edge`
  by product+identifier heuristics (fallback: onprem).
- **Custom-skinned globe**: dark stylised material (no Earth texture) with 7 hand-crafted continent polygons
  rendered via GeoJSON `polygonsData`; each continent labeled and colored by layer.
- **Backend payload additions**: `continents[]` (GeoJSON), `layer_stats[]` (count+risk+top per layer),
  `points[].layer/layer_label/color`, `paths[].layers_traversed`, `steps[].layer/layer_label/layer_color`.
- **Layer Legend sidebar**: hover to dim other continents and pan the camera; shows count + risk bar + top asset.
- **Layer badges** on every BreachHop and PathCard step; PathCards display the `layers_traversed` sequence.
- **Seed enrichment**: idempotently attaches 7 diverse assets to the Dogfood engagement (Okta SaaS, GitLab code,
  Jenkins CI, CloudFront cloud, Win11 workstation endpoint, UniFi camera edge, AD DC01 onprem) so every
  continent populates on the demo.

## Iteration 5 — Auth + Real Tools + Docker/Terraform + B/W Cyberpunk Rebrand (100% pass)
### Auth (JWT — replaces the UI-only role switcher)
- `backend/auth.py` — bcrypt + PyJWT, 4 roles (admin > approver > operator > viewer), httpOnly cookies +
  Bearer header + `?token=` SSE fallback.
- Admin seeded idempotently from `SEED_ADMIN_EMAIL` / `SEED_ADMIN_PASSWORD`; hash rotates when the env password changes.
- Brute-force lockout (5 failures → 15 min per (IP, email)).
- All `/api/*` routes protected except `/api/auth/login`, `/api/auth/refresh`, `/api/health`, `/api/readiness`, `/api/`.
- Frontend: `AuthProvider` + `ProtectedShell` route guard, `/login` page, `/users` admin page (create/delete users),
  role-aware UI (approver+ can approve, operator can drive, viewer read-only).

### Real security-tool execution
- `backend/real_tools.py` — subprocess adapters for `nmap`, `nikto`, `wpscan`, `dirbust` (gobuster/dirb), `sqlmap`.
- `TOOL_MODE=auto|real|sim` env gates the boundary; falls back to `sim_tools` when binary missing.
- Every tool run is still scope-checked against the signed RoE (SEC-02) before execution.
- New endpoints: `GET /api/tools/availability` and `GET /api/tools` returns `installed` + `effective_mode` + `binary_path`.

### Deployment stack (GitHub-ready, deploy to AWS manually)
- `backend/Dockerfile` (python:3.11-slim + nmap + gobuster + dirb + sqlmap + wapiti + nikto (git clone) + wpscan (gem))
- `frontend/Dockerfile` (multi-stage node build → nginx runtime) + `frontend/nginx.conf` (SSE-friendly reverse-proxy)
- `docker-compose.yml` (mongo + backend + frontend) — one-command local + prod
- `deploy/terraform/` — single-EC2 stack (VPC + IGW + Subnet + SG + Ubuntu 22.04 + EIP + auto-generated ED25519 keypair)
  with `user-data.sh.tmpl` cloud-init that installs Docker, clones the repo, writes `.env` from Terraform vars,
  brings the stack up, provisions Let's Encrypt via certbot + host nginx when a domain is set.
- `deploy/cloudformation/stack.yaml` — CloudFormation twin (single `aws cloudformation deploy` call).
- `deploy/README.md` — three deployment paths (Docker Compose / Terraform / CloudFormation).
- Root `README.md`, `.env.example`, `.gitignore` — GitHub-ready.

### B/W Cyberpunk rebrand + `8π` logo + `app.8pi.ai` domain
- Full palette overhaul: pure black surfaces, whites/grays for hierarchy, **hot magenta `#FF00A0` as the ONE
  signal accent** (critical severity, kill switch, breach animation, crown-jewel markers, primary CTAs).
- New `EightPiLogo` component (italic 8 + magenta π with glow) used in Sidebar, Login page, favicon SVG.
- Cyberpunk CSS effects: scanline overlays, corner-frame markers, glitch-hover text, CRT vignette, flicker,
  Space Mono terminal typography.
- Ecosystem globe: continents rendered in grayscale (wayfinding by position + label), points colored by role
  (`entry=white`, `pivot=gray`, `crown=magenta`), atmosphere glow is magenta, breach animation walks white → magenta.
- Terraform + docs updated for `domain = "app.8pi.ai"` default; marketing site at `8pi.ai` deployed separately.

## Iteration 6 — Red Scope incident hub + Archive engagements (100% pass, 8/8 backend)
### Red Scope (`backend/red_scope.py`, `frontend/src/pages/RedScope.jsx`)
- New left-sidebar section pinned ABOVE Operations, styled with the reserved blood-red (#FF2A2A)
  incident accent + blinking marker (Red Scope IS the incident hub, so blood-red is intentional here).
- `GET /api/red-scope` aggregates every blood-red signal: halted engagements (kill switch), critical/
  confirmed findings, and pending exploit-intensity approvals — with per-engagement name enrichment.
- **Adversary Copilot** chat: operator describes an attack in natural language → `POST /api/red-scope/chat`
  routes through the Model Gateway (hosted Claude via LLM API key) → returns a conversational reply
  + a structured, sanitized attack draft (name/role/max_intensity/tools/target/technique/rationale).
- Draft editor: operator reviews/edits (tool toggles, role, intensity) → **Save to Registry**
  (`POST /api/red-scope/agents`) creates a real agent record (`origin="red-scope"`, `red_scope_brief` attached,
  promotion_state=dev). Reuses new `create_agent_core()` factored out of `agent_runtime.py`.
- RBAC: `/red-scope/chat` and `/red-scope/agents` require operator+ (viewers get 403); `GET /red-scope` is read-only.
- **Attach-to-copilot (follow-up):** every feed item (finding / halted engagement / exploit approval) has a `+`
  button that attaches it as a removable target chip above the copilot input. `POST /red-scope/chat` accepts a
  `context[]` array (kind/label/detail) injected into the prompt so the AI designs the attack/agent around those
  specific items; sending with only targets (empty message) auto-prompts. Feed findings are enriched with their
  asset `target` host so the copilot has the destination without asking.

### Archive engagements (`backend/orchestration.py`, `frontend/src/pages/Dashboard.jsx`)
- `engagements` gains `archived` (default False). `POST /engagements/{id}/archive` + `/unarchive` with audit events.
- `GET /engagements` hides archived by default (`archived:{$ne:True}` — backward compatible for pre-existing/seed docs);
  `?include_archived=1` reveals all. Dashboard "Show Archived" toggle + per-card archive/unarchive button
  (`archive-engagement-{id}` / `unarchive-engagement-{id}`), "Archived" badge on archived cards.

### Architecture clarification for the user
- Agents are NATIVE 8pi MongoDB records (`agents` collection), NOT Google Agent Platform. Their reasoning
  runs through the Model Gateway, which calls Anthropic Claude via AWS Bedrock (boto3), with a deterministic
  on-prem fallback. Deployment stack is AWS (EC2 + Terraform/CloudFormation), not GCP. User confirmed: keep
  AWS + native registry.

### AWS Bedrock migration + legacy integration cleanup (2026-07-05, verified via curl)
- **Goal:** hand codebase to external team for AWS deploy; remove all third-party build-platform traces; use Bedrock (Opus 4.8).
- Added `backend/bedrock.py`: boto3 `bedrock-runtime` Converse + ConverseStream helpers. Config via
  `AWS_REGION` (default `us-east-1`) + `BEDROCK_MODEL_ID` (default geo profile `us.anthropic.claude-opus-4-8`),
  boto3 default credential chain (no static keys).
- `model_gateway.py`: `_call_hosted` now runs Bedrock `converse` via `asyncio.to_thread`; deterministic local
  responder retained as fallback. `hosted-frontier` route → provider `aws-bedrock`, model = `BEDROCK_MODEL_ID`.
- `attack_path.py`: SSE stream now pulls Bedrock ConverseStream deltas on a worker thread via an asyncio.Queue;
  word-by-word local `_fallback()` retained when Bedrock unreachable.
- Removed legacy third-party LLM SDK package + its hosted `litellm` wheel from `requirements.txt` (and uninstalled).
- `.env` / `.env.example` / `docker-compose.yml`: dropped legacy hosted-LLM key var; added `AWS_REGION` +
  `BEDROCK_MODEL_ID` (+ optional AWS_* passthrough).
- IaC: Terraform (`variables.tf`, `main.tf`, `user-data.sh.tmpl`) + CloudFormation (`stack.yaml`) now attach an
  **IAM instance role** granting `bedrock:InvokeModel*` (keyless), replaced the legacy hosted-LLM key var with
  `bedrock_model_id` / region. `README.md` + `deploy/README.md` document Bedrock + model-access prereqs.
- **Verified:** `/api/model/routes` shows aws-bedrock/opus-4-8; `/api/model/infer` reason task falls back to
  local when no creds; sensitive traffic stays pinned local (SEC-05); attack-path SSE degrades gracefully.
  Zero third-party build-platform strings remain in code/config/deploy.

## Prioritized Backlog / Next

### Bug fix (2026-07-05, verified via testing_agent iteration 8)
- **RoE tab crash `tools.map is not a function`**: `api.tools()` returned the full `{tools, tool_mode}` envelope instead of the array. Fixed to return `r.data.tools` + added `Array.isArray` guard in RoeTab. All 10 engagement tabs render clean.


### Code-quality review (Iteration 7 — applied 2026-07-05, regression 100%)
Applied (safe, verified non-breaking):
- `model_gateway.py`: replaced dynamic `__import__("datetime")` with explicit `from datetime import datetime, timezone`.
- `red_scope.py`: defensive `draft=None` init in `_extract_draft`.
- React keys: RedScope chat messages use stable ids; FindingsTab evidence / ConsoleTab steps / AssetsTab versions use composite keys (no bare index).
- Dashboard LiveLog poll now `console.debug`s failures instead of swallowing.

Deferred WITH rationale (not applied — would risk regressions / misread by the linter):
- **Auth tokens in localStorage → httpOnly-only**: intentional transport (Bearer header for axios + `?token=` for SSE/EventSource which can't set headers). Removing it breaks the SPA; auth changes require the integration path. Not a bug.
- **"Undefined variable" flags** (reporting.py `f`, auth.py `payload`/`u`, attack_path.py `a`/`r`): FALSE POSITIVES — generator/loop locals & try/except-with-raise; always defined.
- **High-complexity refactors** (attack_path `_classify_layer`/`compute`, agent_runtime `run_offensive`/`run_defensive`, scope_check, run_sensing, RedScope/EngagementDetail/Dashboard/AuthProvider splits): high regression risk on a tested system; several based on misreading (RedScope is the incident hub, not a "scope editor").
- **useEffect/useCallback dependency additions** in ConsoleTab/ThreatMapTab/AttackPathTab/VulnTab/RoeTab/AuditTab: intentionally scoped (eslint-disabled); adding deps risks infinite fetch/render loops in the graph/globe components.

- P1: WebSocket live-refresh for Console/audit stream (currently manual reload after actions).
- P1: RoE re-versioning UI (new signed version) — backend already immutable-on-sign.
- P1: wpscan/dirbust surfaced as explicit findings; MITRE technique catalog page.
- P2: Real containerized tool execution + true per-engagement network isolation (spec NFR-ISO-01).
- P2: OpenMythos local model swap-in (C-11), multi-tenant/SSO (Phase 3), data flywheel.
- P2: Auth + full RBAC enforcement (deferred per user; roles are UI-level now).
