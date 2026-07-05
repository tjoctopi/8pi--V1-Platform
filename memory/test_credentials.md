# Test Credentials — 8pi v1

## Admin (seeded from backend/.env on boot)
- **Email**: `admin@8pi.io`
- **Password**: `8pi-admin-changeme`
- **Role**: `admin`

The admin account is seeded idempotently by `backend/auth.py::seed_admin()` from the env vars
`SEED_ADMIN_EMAIL` / `SEED_ADMIN_PASSWORD`. If the env password changes, the hash is rotated on
next backend restart. Rotate this default in production.

## Auth flow (JWT)
- `POST /api/auth/login` → `{access_token, refresh_token, user}`  (sets httpOnly cookies too)
- `POST /api/auth/refresh` → rotates access token (from refresh cookie or body)
- `GET /api/auth/me` → current user
- `POST /api/auth/logout` → clears cookies
- `POST /api/auth/change-password` → self-service password change
- Admin-only: `GET/POST/DELETE /api/auth/users` (user management, seen in UI at `/users`)

## Roles (hierarchical — admin > approver > operator > viewer)
- **admin**    — everything + user management
- **approver** — approve / deny exploit approvals + everything below
- **operator** — drive the pipeline (RoE, sensing, tools, agents)
- **viewer**   — read-only

The old client-side role switcher has been removed. Role is now taken from the JWT (`role` claim)
and enforced server-side (see `orchestration.py::approve/deny`).

## Seeded demo data
- Active engagement: **"Dogfood — 8pi Internal Estate"** — RoE signed (max intensity: exploit),
  35 assets (7-way ecosystem: endpoint, saas, cloud, dev, code, onprem, edge), ~41 findings,
  agent runs recorded, exploit approvals pending.

## Notes for testers
- All `/api/*` routes require a Bearer token EXCEPT `/api/auth/login`, `/api/auth/refresh`,
  `/api/health`, `/api/readiness`, `/api/`.
- The SSE endpoint `/api/engagements/{id}/attack-path/stream` accepts `?token=<jwt>` as a fallback
  because browsers can't attach headers to `EventSource`.
- Security tools now run REAL CLI binaries (nmap / nikto / wpscan / dirbust / sqlmap) when installed,
  or fall back to deterministic sim adapters when not. Every run is still scope-checked against
  the signed RoE.
- Kill switch requires typing `HALT` in the confirm modal (`[data-testid="kill-confirm-input"]`).

## Frontend data-testids for auth
- `login-page`, `login-email`, `login-password`, `login-submit`, `login-error`
- `user-menu`, `logout-btn`, `user-menu-users` (admin only)
- `users-page`, `user-add-btn`, `user-form-email`, `user-form-password`, `user-form-name`,
  `user-form-role`, `user-form-submit`, `user-row-{id}`, `user-delete-{id}`
