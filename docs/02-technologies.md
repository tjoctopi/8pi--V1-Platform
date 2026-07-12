# 2 · Technologies & why

Every technology choice serves one of three goals: **safety** (nothing escapes
the envelope), **trust** (results are provable and auditable), or **portability**
(the full test suite runs with zero external services).

## Language & core

| Technology | Why |
|-----------|-----|
| **Python 3.11+** | Rich security-tooling ecosystem; `match`, precise typing, fast enough (the heavy work is in the sandboxed tools, not Python). |
| **`src/` layout + hatchling + `uv`** | Clean packaging, reproducible venvs, wheel-buildable for distribution. |
| **pydantic v2 `StrictModel`** | Every boundary object is a **validated, typed contract**. Agents pass a typed `ToolProfile`, never a raw command line — so there is *no shell-injection surface* (rule #2). Strict mode rejects unknown/loose fields. |
| **pytest** | ~456 tests including per-sprint **exit-gate** tests that encode acceptance criteria. |
| **ruff + mypy `--strict`** | Lint + full static typing, kept green. Catches whole classes of bugs before runtime. |
| **Typer + Rich** | Ergonomic CLI (`intel`, `assess`, `engage`, `campaign`, `coverage`, …) with readable terminal output. |

## Isolation & execution

| Technology | Why |
|-----------|-----|
| **Docker (ephemeral, per-invocation containers)** | Each tool runs in a throwaway container joined only to the **engagement-scoped network** — blast radius is bounded and nothing touches the host/corporate network. Hardened: `--read-only`, `--cap-drop ALL` (relaxed only for the MSF interpreter), `--security-opt no-new-privileges`, `--pids-limit`, noexec tmpfs. |
| **Pluggable sandbox backends (Docker / Local / Noop)** | Docker for production; Local/Noop for tests → the suite needs **no Docker**. |
| **gVisor-ready (`--runtime runsc`)** | Optional kernel-level isolation for higher-assurance deployments. |

## Model layer (BYOM — rule #4)

| Technology | Why |
|-----------|-----|
| **LiteLLM** | One API across providers; the gateway routes a *task tier* (frontier/local) to whatever model is configured — **no model is hard-coded**. |
| **Fireworks AI** (OSS models, e.g. GLM) | Cost-effective open-weight inference for the bulk/local tier. Key via `FIREWORKS_API_KEY` (env only). |
| **Anthropic Claude** (frontier tier) | High-capability reasoning where it matters. Key via `ANTHROPIC_API_KEY` (env only). |
| **Deterministic MockProvider** | Backs tests — no API key needed in CI. |

> Secrets are **only** ever read from a gitignored `.env` — never printed, never
> committed.

## Knowledge, graph & events

| Technology | Why |
|-----------|-----|
| **NetworkX** | In-memory attack graph (assets, services, reachability, privilege graph, AD attack paths) — Dijkstra/shortest-path for kill-chain routing. |
| **Neo4j backend (optional)** | Engagement-scoped graph store for scale; driver-injectable, tested against a recording fake (no server needed). |
| **Event bus: in-memory + Redis Streams** | Blackboard mutations emit events for the Orchestrator/Blue Sentry. `fakeredis` in tests → no Redis needed. |

## Audit & correlation

| Technology | Why |
|-----------|-----|
| **Hash-chained audit (in-mem / SQLite / Postgres)** | Tamper-evident record of every action; `psycopg` for Postgres in production, SQLite by default, in-mem for tests. |
| **NVD 2.0 + CISA KEV ingest** | Real CVE correlation: CPE `cpeMatch` → correct version intervals; KEV marks known-exploited. Bundled seed for offline/tests; live fetch is integration-only. |
| **Platt + isotonic calibration, Bayesian evidence fusion** | Findings carry a **calibrated exploitability probability**, not raw CVSS — so prioritisation reflects reality (measured by a Brier/ECE eval harness). |
| **MLflow (optional)** | Eval/experiment tracking; `LocalJsonTracker` default. |

## Security tools integrated (20)

Each is wrapped behind the same safety envelope; read-only tools are
default-allowed, intrusive ones are `mutating` (refused under read-only RoE),
commercial ones are `licensed` (refused unless the RoE enables them).

| Category | Tools |
|----------|-------|
| **Recon / discovery** | `nmap`, `masscan`, `httpx`, `ffuf`, `subfinder`, `amass`, `searchsploit` |
| **Web** | `nuclei`, `nikto`, `wpscan`, `katana`, `dalfox`, `http_probe` |
| **Exploitation / confirm** | `metasploit`, `metasploit_check`, `sqlmap_confirm` |
| **Identity / AD** | `bloodhound`, `kerberoast` |
| **Licensed (gated)** | `nessus`, `burp_enterprise` |

Details of which agent drives which tool, and why, are in
[Agents & tools →](03-agents-and-tools.md).
