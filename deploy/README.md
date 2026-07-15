# 8π — Deploying to AWS

> **What deploys:** the **real engine** — `attack_engine.api` (FastAPI) + the React SPA
> (nginx). **No MongoDB.** Same-origin: nginx reverse-proxies `/api` → the `api` service,
> so cookies + SSE work. The legacy Mongo prototype (`backend/`) is deprecated and no
> longer built (see `backend/DEPRECATED.md`).
>
> **Domains:** app runs at `app.8pi.ai`; the marketing site (`8pi.ai`) is separate.

## The one thing that makes this deploy unusual
The platform runs **real offensive tools inside sandboxed Docker containers**, which it
spawns on the **host Docker** via a mounted socket (docker-out-of-docker). So:
- the deploy host must be **Docker-capable**, and the `api` container mounts
  `/var/run/docker.sock` — **treat that node as privileged and isolated**;
- set **`AE_SANDBOX_NETWORK`** to the host network the tool containers must join to reach
  the authorized targets (scope is still enforced deny-by-default);
- **pre-pull the tool images** on the host so first scans don't stall (see below).

---

## Supported paths

| Path | Time | You need |
| --- | --- | --- |
| **A · Docker Compose on an EC2** | ~10 min | An EC2 with Docker + a public IP |
| **B · Terraform single-EC2** | ~10 min | AWS creds + Terraform ≥ 1.6 |
| **C · CloudFormation single-EC2** | ~10 min | AWS CLI |

All three deploy the **real engine** stack. B & C provision the infra (VPC / EC2 / EIP /
SG / SSM) and run `docker compose up` on first boot with the engine's `AE_*` env.

---

## Prerequisites (all paths)

1. **A model provider (BYOM).** The gateway routes via LiteLLM. Set one or both:
   - `FIREWORKS_API_KEY` and/or `ANTHROPIC_API_KEY` in `.env`.
   - (AWS Bedrock is possible through LiteLLM, but the default is Fireworks/Anthropic keys.)
   - For a keyless smoke test set `AE_MODEL_MOCK=true` (deterministic, no real reasoning).
2. **A JWT secret** — `python3 -c "import secrets; print(secrets.token_hex(32))"` → `AE_API_JWT_SECRET`.
3. **Admin credentials** — `AE_API_ADMIN_EMAIL` + `AE_API_ADMIN_PASSWORD`, seeded on first boot.
4. **`AE_SANDBOX_NETWORK`** — the Docker network the tool containers join to reach targets.
5. **(Optional) A domain + TLS** (Let's Encrypt / ACM).

---

## Path A · Docker Compose on your EC2

### 1. Launch an EC2
Ubuntu 22.04, **t3.large** (the tool executor is CPU/network-heavy), 40 GB gp3 (tool
images are large), security group inbound 22/80/443.

### 2. Bootstrap Docker
```bash
sudo apt update && sudo apt install -y ca-certificates curl gnupg git
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt update && sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER && newgrp docker
```

### 3. Clone + configure
```bash
git clone https://github.com/YOUR-ORG/8pi.git && cd 8pi
cp .env.example .env
$EDITOR .env    # fill: AE_API_JWT_SECRET, AE_API_ADMIN_EMAIL/PASSWORD, FIREWORKS_API_KEY
                #       and/or ANTHROPIC_API_KEY, AE_API_ORIGINS, AE_SANDBOX_NETWORK
```

### 4. Create the tool network + pre-pull tool images
```bash
# the network the sandboxed tools join (must match AE_SANDBOX_NETWORK in .env)
docker network create ae_targets

# pre-pull the tool images so first scans don't stall
for img in instrumentisto/nmap:latest projectdiscovery/httpx:latest \
           projectdiscovery/nuclei:latest projectdiscovery/katana:latest secsi/ffuf:latest; do
  docker pull "$img"
done
# seed nuclei templates into a named volume (air-gapped scans)
docker run --rm -v ae-nuclei-templates:/root/nuclei-templates projectdiscovery/nuclei:latest -update-templates
```

### 5. Bring it up
```bash
docker compose up -d --build
docker compose ps
docker compose logs -f api        # watch engine init + admin seed
```
Open **http://<ec2-public-ip>** and sign in with the admin creds from `.env`.

### 6. (Optional) HTTPS
Set `HTTP_PORT=8080` in `.env`, put nginx/Caddy on 443 forwarding to `127.0.0.1:8080`,
and issue a cert with certbot/ACM. (An nginx TLS block is in `deploy/terraform/user-data.sh.tmpl`.)

---

## Production state backends
Defaults are in-process (SQLite audit, in-memory event bus, NetworkX graph) — fine for a
pilot. For production, point at managed services in `.env` (**no code change**):
```bash
AE_AUDIT_BACKEND=postgres      AE_AUDIT_POSTGRES_DSN=postgresql://ae:PASS@rds-host:5432/attack_engine
AE_EVENTBUS_BACKEND=redis      AE_EVENTBUS_REDIS_URL=redis://:PASS@elasticache-host:6379/0
AE_GRAPH_BACKEND=neo4j         AE_NEO4J_URL=bolt://neo4j-host:7687  AE_NEO4J_USER=neo4j  AE_NEO4J_PASSWORD=PASS
```
The `api` container image already includes the drivers. DBs must be reachable from the
API's security group on 5432/6379/7687 **inside the VPC (never public).**

---

## Path B · Terraform (one command)
```bash
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars   # repo_url, branch=dev, ae_api_jwt_secret, ae_api_admin_*,
                           # fireworks_api_key and/or anthropic_api_key, domain + tls_email
terraform init && terraform apply
```
Grab the outputs (`app_url`, `ssh_command`). Watch boot with
`sudo tail -f /var/log/8pi-bootstrap.log` (~5 min). The instance has an **SSM** role, so you
can also open a shell via Session Manager with no inbound SSH. Bootstrap writes the engine
`AE_*` `.env`, creates the tool network, pre-pulls tool images, and brings up `api` + `frontend`.

## Path C · CloudFormation
```bash
aws cloudformation deploy \
  --stack-name 8pi-prod \
  --template-file deploy/cloudformation/stack.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    RepoUrl=https://github.com/YOUR-ORG/8pi.git Branch=dev \
    AeApiJwtSecret="$(python3 -c 'import secrets;print(secrets.token_hex(32))')" \
    AeApiAdminEmail=admin@8pi.ai AeApiAdminPassword=REPLACE_ME \
    FireworksApiKey=REPLACE_ME AeSandboxNetwork=ae_targets \
    SshCidr=0.0.0.0/0
```
Both B & C provision an IAM role with **`AmazonSSMManagedInstanceCore`** (Session Manager;
no Bedrock — the model gateway is BYOM via API keys).

---

## Operations

```bash
docker compose logs -f api          # engine init, audit chain, tool runs, LLM calls
docker compose logs -f frontend     # nginx access logs
docker compose up -d --build        # upgrade (rebuilds api + frontend)
```

**Backup** (default SQLite state lives in the `ae_data` volume):
```bash
docker run --rm -v 8pi_ae_data:/data -v "$PWD":/backup alpine \
  tar czf /backup/ae_data-$(date +%F).tgz -C /data .
```
(If you moved audit to Postgres, back up the RDS instance instead.)

**Rotate the JWT secret:** edit `.env` → new `AE_API_JWT_SECRET` → `docker compose restart api`.
All sessions invalidate; users re-login.

---

## Troubleshooting

- **`bind: address already in use` on 80** — set `HTTP_PORT=8080` in `.env`.
- **`/api/health` ok but scans do nothing / "permission denied … docker.sock"** — the `api`
  container can't reach the host Docker. Confirm `/var/run/docker.sock` is mounted and the
  host user/group can access it.
- **First scan stalls** — tool images not pulled or the templates volume is empty. Re-run step 4.
- **Tools can't reach targets** — `AE_SANDBOX_NETWORK` doesn't match a host network that
  routes to the targets, or the targets aren't in the signed RoE (refused deny-by-default).
- **Attack-path / live progress SSE never streams** — nginx buffering; the `/api/` block ships
  with `proxy_buffering off` (keep it).
- **Model calls fail** — no `FIREWORKS_API_KEY`/`ANTHROPIC_API_KEY` set (and `AE_MODEL_MOCK`
  not `true`). Check `docker compose logs api` for the provider line at startup.

---

## Security notes

- Frontend is same-origin with the API via nginx; the API enforces scope, gates, kill switch,
  and writes a **hash-chained audit log** as the record every action was in-scope.
- Secrets (`AE_API_JWT_SECRET`, model keys, DB creds) live only in `.env` / a secrets manager —
  never commit them.
- The `api` node holds the Docker socket → it can launch containers. Isolate it; scope its
  egress to authorized targets.
- Offensive actions run **only** inside a signed, unexpired RoE. You are responsible for
  written authorization from the target owner.
