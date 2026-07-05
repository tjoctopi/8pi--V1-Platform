# 8pi — Agentic Cybersecurity Platform (v1)

> **Purple-team console with AI-driven attack-path reasoning.**
> Scoped, RoE-signed engagements → sensing → threat map → attack path (ecosystem globe) → agents → vuln loop → reporting. Every action is auditable via a tamper-evident hash chain.

## Highlights

- **Signed Rules of Engagement + tamper-evident audit chain** (SEC-01, SEC-04)
- **7-layer Ecosystem Attack-Path Globe** (Code · Dev · Cloud · SaaS · Endpoints · On-Prem · Edge/IoT/AI) with animated "Play Breach" walkthroughs
- **Real CLI tools** (nmap, nikto, wpscan, sqlmap, gobuster, dirb) — scope-checked, sim fallback
- **Real Model Gateway** — Anthropic Claude (Opus 4.8) via AWS Bedrock (boto3), with a deterministic on-prem fallback
- **JWT auth** with 4 roles (admin · approver · operator · viewer); brute-force lockout
- **Live SSE mini-logs** on the dashboard; kill-switch that halts every in-flight action
- **Reproducible reporting** (JSON · HTML · PDF)

## Stack

- Backend: **FastAPI + MongoDB (Motor)** — port 8001
- Frontend: **React (CRA) + Tailwind + react-globe.gl** — served by nginx (proxies `/api` → backend)
- Deploy: Docker Compose. AWS via Terraform or CloudFormation (see `deploy/`).

## Local development

```bash
git clone https://github.com/YOUR-ORG/8pi.git && cd 8pi
cp .env.example .env
# Fill: JWT_SECRET (64-hex), SEED_ADMIN_*, AWS_REGION, BEDROCK_MODEL_ID (AWS creds via IAM role / ~/.aws / env)
docker compose up -d --build
open http://localhost                # sign in with SEED_ADMIN_EMAIL / SEED_ADMIN_PASSWORD
```

Backend logs: `docker compose logs -f backend`. Data persists in the `mongo_data` volume.

## Deploying to AWS

See **[`deploy/README.md`](deploy/README.md)** — three paths:

- **A. Docker Compose on your own EC2** (5 min)
- **B. Terraform single-EC2** — `terraform apply` (10 min) — Elastic IP + optional Let's Encrypt
- **C. CloudFormation single-EC2** — one `aws cloudformation deploy` call

## Roles

| Role      | Rank | Can do                                                        |
| --------- | ---- | ------------------------------------------------------------- |
| admin     | 3    | Everything + user management                                  |
| approver  | 2    | Approve / deny exploit-intensity actions + everything below   |
| operator  | 1    | Drive the pipeline: RoE, sensing, run tools, run agents       |
| viewer    | 0    | Read-only — engagements, findings, reports                    |

The admin account is seeded from `SEED_ADMIN_EMAIL` / `SEED_ADMIN_PASSWORD` on first boot (idempotent — updating the env rotates the password).

## Real vs simulated tool execution

`TOOL_MODE` env controls the tool boundary:

- `real` — always call the CLI binary (nmap/nikto/wpscan/…); raise if missing
- `sim`  — always call the deterministic simulated adapter (safe, no network I/O)
- `auto` — call real when the binary is installed, sim fallback (default)

Every tool run is scope-checked against the signed RoE (`SEC-02`) before execution. Out-of-scope targets are refused server-side, no matter which mode is active.

## Repo layout

```
.
├── backend/                    FastAPI backend
│   ├── server.py               entry — mounts routers, CORS, seed hooks
│   ├── auth.py                 JWT auth + admin seeding
│   ├── real_tools.py           subprocess adapters (nmap/nikto/wpscan/dirbust/sqlmap)
│   ├── sim_tools.py            deterministic simulated adapters (fallback)
│   ├── attack_path.py          7-layer ecosystem classifier + globe payload + SSE
│   ├── orchestration.py        engagements, approvals, kill switch
│   ├── model_gateway.py        Anthropic Claude via AWS Bedrock (boto3)
│   ├── sensing.py              asset discovery (via tool boundary)
│   ├── vuln_loop.py            CVE/KEV correlation + remediate/re-test
│   ├── agent_runtime.py        offensive + defensive agent runs
│   ├── reporting.py            JSON / HTML / PDF report
│   ├── seed.py                 idempotent dogfood engagement + ecosystem enrichment
│   └── tests/                  pytest suite
├── frontend/                   React SPA
│   ├── src/pages/tabs/         Attack Path, Console, Findings, Vuln, Audit, Report…
│   └── nginx.conf              reverse-proxy + SSE-friendly buffering
├── docker-compose.yml          local + prod stack (mongo + backend + frontend)
├── .env.example
├── deploy/
│   ├── README.md               ← step-by-step AWS deployment guide
│   ├── terraform/              single-EC2 Terraform
│   └── cloudformation/         single-EC2 CloudFormation
└── memory/
    ├── PRD.md                  product requirements + iteration log
    └── test_credentials.md     seeded creds (updated on env change)
```

## Security posture

- All `/api/*` routes require a valid JWT (except `/api/auth/login`, `/api/auth/refresh`, `/api/health`, `/api/readiness`).
- Cookies: `httponly + secure + samesite=lax`. Bearer token also accepted (`Authorization: Bearer …`).
- SSE streams accept an `?token=` query param since browsers can't set headers on `EventSource`.
- Passwords: bcrypt with per-user salt. 5 failed logins → 15-min lockout per (email, IP).
- Audit chain is append-only + hash-chained; `GET /api/engagements/{id}/audit/verify` re-computes the chain and returns pass/fail.
- Kill switch is a single-user-typed `HALT` confirmation that immediately halts all pending approvals and blocks further tool activity for the engagement (SEC-10).

## License

Proprietary — internal use only.

---

**8pi** · v1.0 · agentic purple-team ops
