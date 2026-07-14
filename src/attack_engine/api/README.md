# 8π Attack Engine — HTTP API (frontend ⇄ engine bridge)

This package is the HTTP shell the composition root (`engine.py`) was designed
for. It serves the **exact `/api/*` contract** the React console (`frontend/`)
already speaks, backed by the **real** engine — no Mongo, no simulation.

```
frontend/ (React, unchanged)
    │  /api/*  (JWT Bearer)
attack_engine.api.app   ── FastAPI shell: auth (JWT+pbkdf2), SQLite user/engagement store
    │
attack_engine.api.adapter ── EngineAdapter: RoE⇄Scope, lifecycle, engine→console JSON
    │
Engine + EngagementManager ── real scope enforcement, verify oracles, kill switch, audit chain
```

## Layout
- `adapter.py` — the seam. Boots one `Engine` + `EngagementManager`; maps the
  console RoE doc → signed engine `Scope`; opens/halts/resumes engagements;
  drives recon/verify/correlate; reads assets/findings/audit back as console JSON.
- `serialize.py` — pure translators (engine `Finding`/`Asset`/`Service`/`AuditEntry`
  → console shapes). Unit-testable with no engine.
- `auth.py` — JWT (PyJWT/HS256) + stdlib `pbkdf2_hmac` passwords. Roles mirror the
  engine RBAC vocabulary (viewer<operator<approver<admin).
- `store.py` — SQLite shell store (users + engagement metadata) — the only state
  the engine deliberately doesn't own.
- `app.py` — FastAPI app wiring the `/api/*` routes to the adapter.

## Run
```bash
pip install -e '.[api]'                 # fastapi, uvicorn, pyjwt

# dev boot (no Docker/keys needed — in-process engine)
AE_ENV=dev AE_SANDBOX_BACKEND=noop AE_MODEL_MOCK=true AE_AUDIT_BACKEND=memory \
AE_API_ADMIN_EMAIL=admin@8pi.local AE_API_ADMIN_PASSWORD=changeme \
  python -m attack_engine.api.app          # → http://0.0.0.0:8000

# real run (Docker sandbox + BYOM keys + sqlite audit) — omit the dev overrides,
# set FIREWORKS_API_KEY / ANTHROPIC_API_KEY, AE_SANDBOX_NETWORK, etc.
```
Point the console at it: `REACT_APP_BACKEND_URL=http://localhost:8000`.

## Env
| var | meaning |
|---|---|
| `AE_API_DB` | shell SQLite path (default `./data/api_shell.db`) |
| `AE_API_JWT_SECRET` | HS256 signing secret (auto-generated per process if unset) |
| `AE_API_ADMIN_EMAIL` / `AE_API_ADMIN_PASSWORD` | seed admin on first boot |
| `AE_API_ORIGINS` | CORS origins, comma-sep (default `http://localhost:3000`) |
| `AE_API_PORT` | listen port (default 8000) |
| `AE_*` | all engine settings (sandbox, audit, model gateway) apply |

## Wiring status
**Phase 1 (live):** auth, engagement lifecycle, RoE draft+signing, recon (`sense`),
assets, verify+correlate (`vuln-scan`), findings, audit + chain verify, stats —
all driven by the real engine.

**Phase 2–4 (placeholders returning valid empty shapes):** tools, agents,
approvals/gates, model gateway, report, attack-path, threat-map, red-scope,
cve-cache, invocations. Filled in as those slices land — see the integration map.

## Design note
Security is **not** re-implemented here. Scope enforcement, human gates, the kill
switch and the hash-chained audit log all live in the engine; this layer exposes
them. Engagement handles are held by a trusted internal service principal; the
HTTP layer enforces which user role may hit which route.
