# 8π — Architecture

A layered, event-driven offensive core with one composition root. Each layer
depends only on the interface below it, so any infrastructure piece is swappable
by config without touching business logic. Nothing wires itself up — the `Engine`
builds every service from `Settings`.

Deeper technical docs live in [`docs/`](docs/); this is the map.

## The layers (top → bottom)
1. **Operator Console** — `frontend/` (React SPA). Scope, run, watch live, read results.
   Talks one JSON contract over `/api`.
2. **API + Adapter** — `src/attack_engine/api/` (FastAPI). Stateless HTTP shell: JWT +
   RBAC, and an `EngineAdapter` that maps the console's rules-of-engagement to a signed
   engine `Scope` and translates engine objects → UI JSON. **Re-implements no security.**
3. **Engine Core** — `Engine` (composition root) + `EngagementManager` (multi-tenant,
   RBAC-isolated). Builds services from config; binds them to one signed engagement each.
4. **Campaign Orchestrator** — `orchestrator/`. Runs the kill chain across a
   privilege/attack graph toward a named objective. Adversary profiles emulate specific
   threat actors (MITRE ATT&CK).
5. **Offensive Operations** — real exploitation modules (Metasploit + custom) that open
   **live sessions**; C2 / post-exploitation over those footholds; identity/AD attack
   paths (BloodHound, Kerberoast); network + identity lateral movement.
6. **Agent Runtime** — one archetype per reasoning role (Surface Mapper, Web Inquisitor,
   Exploit Confirmer, Converter…). New TTPs = a registered tool/exploit module, not a cloned agent.
7. **Tool Runner** — the enforcement boundary. Every tool call passes allowlist / rate-limit /
   rules-of-engagement checks, then runs in an isolated, capability-dropped **Docker sandbox**
   network-scoped to authorized targets.
8. **Confirm Engine** — `verify/` + `correlate/`. Deterministic oracles promote proposed →
   confirmed; calibrated exploit probability vs CVE/KEV + reachability. Only proof confirms.
9. **Authorized Autonomy (governance)** — `governance/`. Immutable hash-chained audit log,
   RBAC with segregation of duty, kill switch, human gates for high-impact actions.
10. **State + Model** — per-engagement blackboard (`knowledge/`), attack/privilege graph,
    event bus (live streaming), and the **BYOM model gateway** (`gateway/`).

## The four non-negotiable rules (every layer obeys)
1. **Propose vs. confirm** — the model proposes the attack; deterministic code confirms
   the exploit. No LLM output is trusted as truth.
2. **Scope at the boundary** — scope/rate/RoE enforced by the Tool Runner service, never by an agent.
3. **Roles, not tool-copies** — one archetype per role; capabilities grow via tool wrappers.
4. **Model-agnostic (BYOM)** — everything routes through the gateway; no model hardcoded.

## Autonomy ladder (from scanner to adversary)
- **T0 Gated** — every controlled action asks first (supervised scanner; safe default).
- **T1 Autonomous in range** — approve the engagement, then it runs the safe kill chain unattended.
- **T2 Autonomous in scope** — full autonomy inside a signed customer scope; only high-impact gates.
- **T3 Continuous** — always-on adversary emulation of the estate.

## Kill chain (autonomous, every step audited)
`recon → weaponize/confirm → exploit → foothold → privilege escalation → lateral movement → objective`
(high-impact actions gated).

## The API layer (how the console reaches the engine)
`EngineAdapter` boots one `Engine` + `EngagementManager`; maps RoE ⇄ `Scope`; runs
recon/verify/correlate as **background jobs** (non-blocking) and streams live progress
over **SSE**. Security stays in the engine; the API only exposes it. Shell-only state
(users + engagement metadata) lives in SQLite; findings/scope/audit live in the engine.

## Pluggable backends (dev → prod by one env var each)
| Concern | Dev / pilot | Production | Interface |
|---|---|---|---|
| Audit log | SQLite | Postgres | `AuditBackend` |
| Event bus | in-process | Redis Streams | `EventBus` |
| Attack graph | NetworkX | Neo4j | `GraphBackend` |
| Tool sandbox | Docker / noop | Docker executor pool | `Sandbox` |
| Model gateway | mock / Fireworks | Fireworks·Anthropic·Bedrock | `ModelGateway` |

## Deployment (summary)
Containerized on AWS. Pilot = one EC2 + Docker Compose; production = ECS/K8s with a
Docker-capable tool-executor node + managed Postgres/Redis/Neo4j. Provisioned via
Terraform/CloudFormation (`deploy/`). The tool executor needs Docker access and is
network-scoped to authorized targets.
