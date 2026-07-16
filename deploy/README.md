# 8π — Deploying to AWS

> **What deploys:** the **real engine** — `attack_engine.api` (FastAPI) + the React SPA
> (nginx). **No MongoDB.** Same-origin: nginx reverse-proxies `/api` → the `api` service.
> The legacy Mongo prototype (`backend/`) is deprecated and not built (see
> `backend/DEPRECATED.md`).

Two ways to deploy, depending on how much you're standing up:

| Path | For | Where |
| --- | --- | --- |
| **A · Docker Compose** | a quick single-host pilot / demo | this dir + repo-root `docker-compose.yml` |
| **B · Terraform + Ansible (canonical)** | the full AWS stack (DBs + range + engine) | [`deploy/iac/`](iac/) |

---

## The one thing that makes this deploy unusual
The platform runs **real offensive tools inside sandboxed Docker containers**, spawned on
the **host Docker** via a mounted socket (docker-out-of-docker). So the host must be
Docker-capable, the `api` container mounts `/var/run/docker.sock` (**treat that node as
privileged + isolated**), and `AE_SANDBOX_NETWORK` must be a host network that reaches the
authorized targets. Tool images should be pre-pulled so first scans don't stall.

---

## Path A · Docker Compose (single-host pilot)

1. **Launch a host** — Ubuntu 22.04, **t3.large**, 40 GB, Docker installed.
2. **Configure**
   ```bash
   git clone <your-fork> && cd 8pi && git checkout dev
   cp .env.example .env
   $EDITOR .env    # AE_API_JWT_SECRET, AE_API_ADMIN_EMAIL/PASSWORD,
                   # FIREWORKS_API_KEY and/or ANTHROPIC_API_KEY, AE_SANDBOX_NETWORK
   ```
3. **Tool network + images**
   ```bash
   docker network create ae_targets   # must match AE_SANDBOX_NETWORK
   for img in instrumentisto/nmap:latest projectdiscovery/httpx:latest \
              projectdiscovery/nuclei:latest projectdiscovery/katana:latest secsi/ffuf:latest; do
     docker pull "$img"; done
   docker run --rm -v ae-nuclei-templates:/root/nuclei-templates \
     projectdiscovery/nuclei:latest -update-templates
   ```
4. **Up**
   ```bash
   docker compose up -d --build
   docker compose logs -f api        # engine init + admin seed
   ```
   Open `http://<host-ip>` and sign in with the admin creds from `.env`.

State defaults to in-process (SQLite audit, in-memory bus, NetworkX). For managed backends,
set `AE_AUDIT_POSTGRES_DSN` / `AE_EVENTBUS_REDIS_URL` / `AE_NEO4J_*` in `.env` — no code change.

---

## Path B · Terraform + Ansible (canonical AWS stack)

The full, validated Infrastructure-as-Code lives in **[`deploy/iac/`](iac/)** — modular
Terraform (isolated VPC, EC2, IAM with keyless-Bedrock + SSM, Secrets Manager, S3 backups;
**us-east-1, SSM-only, no inbound SSH, IMDSv2**) + Ansible that configures the host and
deploys the databases (Postgres/Redis/Neo4j), the range, and the engine + console over SSM.

Follow the two READMEs there:
- **Terraform** — [`deploy/iac/terraform/envs/engine-dev/README.md`](iac/terraform/envs/engine-dev/README.md)
  (`terraform init/plan/apply`; secrets are generated into Secrets Manager, never in tfvars).
- **Ansible** — [`deploy/iac/ansible/README.md`](iac/ansible/README.md)
  (`ansible-galaxy collection install -r requirements.yml` → `ansible-playbook site.yml`).

Connect to the host via **SSM Session Manager** (no SSH key, no inbound 22).

---

## Model gateway (BYOM)
Set `FIREWORKS_API_KEY` and/or `ANTHROPIC_API_KEY`, **or** use **keyless Bedrock**: set
`AE_MODEL_FRONTIER=bedrock/<model-id>` and rely on the EC2 instance role (the `deploy/iac/`
role already grants `bedrock:InvokeModel*`). `AE_MODEL_MOCK=true` gives a keyless, no-reasoning
smoke test.

---

## Security notes
- Frontend is same-origin with the API via nginx; the API enforces scope, gates, kill switch,
  and writes a hash-chained audit log as the record every action was in-scope.
- Secrets live only in `.env` / Secrets Manager — never commit them.
- The `api` node holds the Docker socket → it can launch containers. Isolate it; scope its
  egress to authorized targets.
- Offensive actions run **only** inside a signed, unexpired RoE.
