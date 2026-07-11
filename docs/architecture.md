# Architecture

The engine is a set of cooperating services around a shared **blackboard**.
Agents never call each other directly — they read and write findings to the
Knowledge Store, and the Orchestrator coordinates who runs next. Any agent can
crash and be retried; parallel agents never corrupt a linear handoff.

```
                         ┌───────────────────────────────────────────┐
                         │              Orchestrator                   │  (Sprint 2)
                         │   plan DAG · dispatch · enforce gates        │
                         └───────────────┬─────────────────────────────┘
                                         │ reads/writes events
     ┌───────────────────────────────────┴───────────────────────────────────┐
     │                          Event Bus (blackboard)                          │
     │              InMemory (tests) · Redis Streams (prod)                     │
     └───┬───────────────┬───────────────────┬───────────────────┬────────────┘
         │               │                   │                   │
   ┌─────▼─────┐   ┌──────▼──────┐     ┌──────▼──────┐     ┌──────▼──────┐
   │  Agents   │   │  Knowledge  │     │ Tool Runner │     │ Blue Sentry │  (Sprint 2)
   │ (runtime) │   │   Store     │     │  (boundary) │     │  tails all  │
   │           │   │ graph+dedup │     │ scope/RoE/  │     │   events    │
   │ Surface   │   │ findings    │     │ ratelimit/  │     └─────────────┘
   │ Mapper... │   │ reachability│     │ sandbox     │
   └─────┬─────┘   └─────────────┘     └──────┬──────┘
         │  model calls                        │ runs tools in
   ┌─────▼─────────────┐               ┌───────▼───────────┐
   │  BYOM Gateway     │               │  Sandbox          │
   │  (LiteLLM →       │               │  Docker/gVisor    │
   │   Fireworks OSS)  │               │  (ephemeral, net- │
   └───────────────────┘               │   scoped)         │
                                       └───────────────────┘

           ┌───────────────────────────────────────────────────┐
           │   Governance (cross-cutting, every action)          │
           │   Immutable hash-chained Audit Log · Human Gates     │
           └───────────────────────────────────────────────────┘
```

## The full coordinated loop (spec §3)

```
plan → recon → verify → correlate → exploit-confirm → convert → re-test
 (1)    (2)      (3)       (4)           (5) gate       (6) gate   (7)
```

Steps 1–4 are autonomous and safe (read-only / confirmation-only). Steps 5–7
touch real change and are **gated** behind a human. Blue Sentry observes the
whole run in parallel.

**Sprint 0 implements the spine + step 2 (Surface Mapper).** Steps 3–7 land in
later sprints; the interfaces they plug into (findings lifecycle, event types,
gates, graph reachability) already exist.

## Component → module map

| Component | Module | Rule enforced |
|-----------|--------|---------------|
| Scope enforcement (radix-trie CIDR) | `toolrunner/scope.py` | #2 scope at boundary |
| Rate limiting (token bucket) | `toolrunner/ratelimit.py` | #2 |
| Tool Runner (`run()` boundary) | `toolrunner/runner.py` | #2, #3 |
| Tool registry + wrappers | `toolrunner/registry.py`, `wrappers/` | #3 roles-not-copies |
| Sandbox (Docker/gVisor) | `toolrunner/sandbox.py` | isolation |
| Audit log (hash chain) | `governance/audit.py` | governance |
| Human gates | `governance/gates.py` | governance |
| RoE evaluation | `governance/roe.py` | #2 |
| Knowledge Store (blackboard) | `knowledge/store.py` | #1 propose/verify |
| Attack graph + reachability | `knowledge/graph.py` | accuracy |
| Union-find dedup | `knowledge/dedup.py` | accuracy |
| Event bus | `eventbus/` | robust coordination |
| BYOM gateway | `gateway/` | #4 model-agnostic |
| Agent runtime | `agents/base.py` | — |
| Surface Mapper | `agents/archetypes/recon.py` | #1, #3 |
| Composition root | `engine.py` | — |

## The propose → verify → confirm lifecycle (rule #1)

```
PROPOSED ──(oracle passes)──▶ VERIFIED ──(reachable + scored)──▶ CONFIRMED
    │                             │
    └──────(oracle fails)─────────┴──────────────▶ REJECTED
```

`Finding.promote()` is the only way to change state, and it rejects illegal
transitions in code — a model can never write `state="confirmed"`. The verify
and correlate stages (oracles, CVE/KEV matching, Bayesian scoring, calibration)
arrive in Sprint 1.

## Why the boundary and the audit log come first

The two things that must exist before any offensive tool is wired are **scope
enforcement at the Tool Runner boundary** and the **immutable audit log**.
Everything else can iterate; these cannot be retrofitted safely. Both are built
and tested in Sprint 0 (`tests/toolrunner/test_scope.py`,
`tests/governance/test_audit.py`, `tests/test_sprint0_exit_gate.py`).
