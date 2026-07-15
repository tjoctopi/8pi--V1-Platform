# ⚠️ DEPRECATED — legacy prototype backend

This `backend/` directory is the **original prototype** (FastAPI + MongoDB + Bedrock,
with simulated tooling / canned CVE feed / faked detection). It is **no longer the
deployed backend** and is **not built by `docker-compose.yml`**.

The product now runs on the **real engine** via **`src/attack_engine/api/`** —
scope-enforced Tool Runner, propose→verify→confirm oracles, calibrated
exploitability, the offensive O0–O6 layers, and a hash-chained audit log. The
deployment builds `deploy/api.Dockerfile` and the frontend proxies `/api` → the
`api` service.

Kept here only for reference / history. Do not add features to it. New work goes
in `src/attack_engine/` and `src/attack_engine/api/`.

See: [`architecture.md`](../architecture.md), [`phases.md`](../phases.md).
