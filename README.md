# 8π Coordinated Attack Engine

> The full purple-team loop — coordinated, robust, and accuracy-first — built on
> the best available open tooling and a BYOM (Bring-Your-Own-Model) layer.

This is **one coordinated attack mechanism**, not five disconnected agents. It
runs the full purple-team loop end to end:

```
plan → recon → verify → correlate → exploit-confirm → convert → re-test
```

Steps 1–4 are fully autonomous and safe (read-only / confirmation-only).
Steps 5–7 touch real change and are **gated** behind a human. The Blue Sentry
agent observes the entire run in parallel.

## The four non-negotiable rules

Every component obeys these. They are enforced *structurally* — in code and
schema — not by convention:

1. **Propose vs. verify.** The model/agent **proposes**; deterministic code
   **verifies**. No finding is "confirmed" on an LLM's say-so — only a passed
   verification oracle promotes it. (`schemas/findings.py`, `verify/`)
2. **Scope at the boundary.** Allowlists, rate limits, and RoE are enforced by
   the Tool Runner, never by an agent. An out-of-scope target is refused
   *before* any tool executes. (`toolrunner/scope.py`)
3. **Roles, not tool-copies.** One agent archetype per reasoning role; tools
   swap via a registry. Adding "another way of attacking" = registering a tool
   wrapper, not cloning an agent. (`toolrunner/registry.py`, `agents/`)
4. **Model-agnostic (BYOM).** No model is hardcoded. Everything routes through
   the gateway; the specialized model swaps in the day it wins the eval.
   (`gateway/`)

**Governance is a feature.** Every tool call, proposed action, and model
decision is written to an immutable, hash-chained audit log tied to a signed
engagement. Anything with real-world effect passes a human-in-the-loop gate.

## Status: Sprint 3 complete — hardened & proven (RBAC, Neo4j, NVD/KEV, eval)

| Component | Module | Status |
|-----------|--------|--------|
| Scope enforcement (radix-trie CIDR, rate limits) | `toolrunner/scope.py` | ✅ Sprint 0 |
| Immutable hash-chained audit log | `governance/audit.py` | ✅ Sprint 0 |
| Knowledge store (NetworkX attack graph, dedup) | `knowledge/` | ✅ Sprint 0 |
| Event bus (blackboard) | `eventbus/` | ✅ Sprint 0 |
| Tool Runner + registry + wrappers | `toolrunner/` | ✅ Sprint 0–1 |
| BYOM gateway (LiteLLM → Fireworks OSS) | `gateway/` | ✅ Sprint 0 |
| Surface Mapper agent | `agents/archetypes/recon.py` | ✅ Sprint 0 |
| Ground-truth range | `range/` | ✅ Sprint 0 |
| **Verification Layer** (oracles, fusion, calibration) | `verify/` | ✅ Sprint 1 |
| **Version interval matching** | `versioning.py` | ✅ Sprint 1 |
| **Exploitability Matcher** (CVE/KEV, Bayesian score) | `correlate/` | ✅ Sprint 1 |
| **Web Inquisitor** (Nuclei/Nikto/WPScan) | `agents/archetypes/web.py` | ✅ Sprint 1 |
| **Exploit-Confirmer** (SQLMap confirm-only, gated) | `agents/archetypes/exploit.py` | ✅ Sprint 1 |
| **Orchestrator** (attack-graph DAG plan + gate enforcement + re-test) | `orchestrator/` | ✅ Sprint 2 |
| **Converter** (finding → proposed patch/ticket, gated apply) | `agents/archetypes/converter.py` | ✅ Sprint 2 |
| **Blue Sentry** (tails the bus, noise vs out-of-RoE) | `defense/` | ✅ Sprint 2 |
| **Close-the-loop re-test + reporting** | `orchestrator/retest.py`, `report.py` | ✅ Sprint 2 |
| **RBAC + multi-engagement isolation** | `governance/rbac.py`, `manager.py` | ✅ Sprint 3 |
| **Neo4j graph backend** (pluggable; NetworkX default) | `knowledge/neo4j_backend.py` | ✅ Sprint 3 |
| **NVD + CISA-KEV ingest** (interval-correct) | `correlate/nvd.py` | ✅ Sprint 3 |
| **Licensed scanners** (Nessus/Burp, procurement-gated) | `toolrunner/wrappers/licensed.py` | ✅ Sprint 3 |
| **Eval harness** (precision/recall + calibration) | `evals/` | ✅ Sprint 3 |
| **Risk map + hardening actions** (partner writeup) | `orchestrator/report.py` | ✅ Sprint 3 |

All 7 agents from the spec are implemented, and the platform is hardened for
multi-tenant, regulated use. Run the pipelines:

```bash
# Autonomous, read-only pipeline (recon → verify → correlate):
attack-engine assess --scope examples/engagement-range.scope.yaml 10.5.0.10

# Full coordinated loop with Orchestrator + Blue Sentry (plan → attack →
# confirm → propose fix → report). Applying fixes + re-test is a separate,
# gated step (Orchestrator.close_loop), never run autonomously:
attack-engine engage --scope examples/engagement-range.scope.yaml 10.5.0.10 --markdown
```

> **The two things that must exist before any offense** are the scope boundary
> and the audit log. Both are built in Sprint 0; neither can be retrofitted
> safely.

## Quickstart (dev)

```bash
uv venv --python 3.11
uv pip install -e ".[dev]"

# Full suite runs with ZERO external services (in-memory / SQLite fallbacks).
pytest

# Lint + types
ruff check src tests
mypy src
```

Copy `.env.example` to `.env` and set `FIREWORKS_API_KEY` to use real models;
otherwise the gateway's deterministic mock backs completions.

## Architecture

The engine is a set of cooperating services around a shared **blackboard**.
Agents don't call each other — they read/write findings to the store, and the
Orchestrator coordinates who runs next. Any agent can crash and be retried;
parallel agents never corrupt a linear handoff.

See [`docs/architecture.md`](docs/architecture.md) and the source-tree layout
in `src/attack_engine/`.

## Safety & authorization

This is an **authorized-use** purple-team tool. It refuses to operate outside a
signed scope, rate-limits every target, sandboxes every tool in an ephemeral
network-scoped container, and gates every real-world-effect action behind a
human. Do not point it at systems you are not explicitly authorized to test.

**Governance is RoE-authoritative.** Which actions require a human gate
(exploit-confirm, apply-fix, containment) is decided by the human-signed RoE
(`scope.roe.gated_actions`), not by an agent spec. An agent spec may *add*
gates but can never remove a RoE-mandated one — a mis-authored or malicious
spec cannot downgrade governance. The autonomous loop (`Orchestrator.run`)
*proposes* fixes but never applies them; applying a change and re-testing
(`Orchestrator.close_loop`) is a separate, gated step that never runs without a
human. Both are enforced in code and covered by regression tests.
