# 8π — Deploying to AWS

> **Domains:** the app runs at **`app.8pi.ai`** (this deploy). The marketing site at
> **`8pi.ai`** is deployed separately (out of scope for this stack — point that A/CNAME
> record at your marketing host of choice).

You have three supported paths, from fastest to most controlled:

| Path              | Time    | You need                          |
| ----------------- | ------- | --------------------------------- |
| A · Docker Compose on any EC2 you already own | 5 min   | An EC2 with Docker + a public IP |
| B · Terraform "one-command" single-EC2        | 10 min  | AWS creds locally + Terraform ≥ 1.6 |
| C · CloudFormation single-EC2 (script)        | 10 min  | AWS CLI |

All three deploy the exact same stack: MongoDB + FastAPI backend + React SPA (nginx). Same-origin — nginx reverse-proxies `/api` to the backend, so cookies + SSE work correctly.

---

## Prerequisites (all paths)

1. **AWS Bedrock access** — The Model Gateway calls Anthropic Claude via Amazon Bedrock (boto3). No API key is stored; the app uses the boto3 default credential chain. Ensure:
   - The runtime (EC2 instance role / ECS task role / `~/.aws` profile) has `bedrock:InvokeModel` + `bedrock:InvokeModelWithResponseStream`. The Terraform and CloudFormation stacks attach an IAM instance role for this automatically.
   - **Model access is enabled** for your chosen model in the Bedrock console for the target region (default `us.anthropic.claude-opus-4-8` — Claude Opus 4.8). Override with `BEDROCK_MODEL_ID` / `AWS_REGION`.
2. **A JWT secret** — Any 64-char hex. Generate with:
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(32))"
   ```
3. **Admin credentials** — Pick an email + password. It's seeded on first boot.
4. **(Optional) A domain name** + an email for Let's Encrypt if you want TLS.

---

## Path A · Docker Compose on your own EC2 (fastest)

### 1. Launch an EC2 (Ubuntu 22.04, t3.medium, 30GB, SG with 22/80/443 inbound).

### 2. SSH in and bootstrap Docker
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
nano .env         # fill: JWT_SECRET, SEED_ADMIN_*, AWS_REGION, BEDROCK_MODEL_ID
```

### 4. Bring it up
```bash
docker compose up -d --build
docker compose ps
docker compose logs -f backend        # watch startup + seed
```
Open **http://<your-ec2-public-ip>** and sign in with the admin credentials from `.env`.

### 5. (Optional) HTTPS with Let's Encrypt
```bash
sudo apt install -y certbot python3-certbot-nginx nginx
sudo systemctl stop docker && docker compose down     # free port 80
sudo certbot certonly --standalone -d <your-domain> -m <your-email> --agree-tos --non-interactive
```
Then edit `.env` → `HTTP_PORT=8080` and put an nginx reverse-proxy on 443 that forwards to `127.0.0.1:8080`. See `deploy/terraform/user-data.sh.tmpl` for a working nginx block you can copy.

---

## Path B · Terraform (one command)

### 1. Install Terraform ≥ 1.6 and set AWS credentials
```bash
brew install terraform                                  # macOS
aws configure                                            # or export AWS_PROFILE / AWS_ACCESS_KEY_ID
```

### 2. Push your 8pi fork to GitHub (or any public git host)
The Terraform stack `git clone`s the repo onto the EC2 on first boot. If your repo is private, add a deploy key or make it public first.

### 3. Fill in secrets
```bash
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars   # paste repo_url, jwt_secret, seed_admin_*, (optional) aws_region, bedrock_model_id, domain + tls_email
```

### 4. Deploy
```bash
terraform init
terraform apply
```
Grab the outputs — `app_url`, `ssh_command`, `bootstrap_log_hint`.

### 5. Watch the boot
```bash
$(terraform output -raw ssh_command)
sudo tail -f /var/log/8pi-bootstrap.log        # ~3–5 min
```
When you see `[8pi] bootstrap complete`, point your DNS `app.8pi.ai` A record at the Elastic IP
from `terraform output public_ip`, then open **https://app.8pi.ai** and sign in.

### 6. (Recommended) Lock SSH down
Change `ssh_cidrs = ["0.0.0.0/0"]` → `["<your-ip>/32"]` in `terraform.tfvars` and re-apply.

### Rotate the admin password
1. Sign in with the seeded credentials.
2. Top-right avatar → *(future: change password)* — for now `curl -X POST /api/auth/change-password` with a Bearer token, or edit the `SEED_ADMIN_PASSWORD` env, `docker compose restart backend`, and log in again.

---

## Path C · CloudFormation (no Terraform)

If your org bans Terraform, use the AWS CLI directly. The CloudFormation template is in `deploy/cloudformation/stack.yaml` — it provisions the same VPC + EC2 + EIP. Deploy with:

```bash
aws cloudformation deploy \
  --stack-name 8pi-prod \
  --template-file deploy/cloudformation/stack.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    RepoUrl=https://github.com/YOUR-ORG/8pi.git \
    JwtSecret="$(python3 -c 'import secrets;print(secrets.token_hex(32))')" \
    SeedAdminEmail=admin@example.com \
    SeedAdminPassword=REPLACE_ME \
    BedrockModelId=us.anthropic.claude-opus-4-8 \
    SshCidr=0.0.0.0/0
```

---

## Operations

### Logs
```bash
docker compose logs -f backend        # audit chain, seed, LLM calls
docker compose logs -f frontend       # nginx access logs
docker compose logs -f mongo
```

### Backup MongoDB
```bash
docker compose exec mongo mongodump --archive=/data/db/backup-$(date +%F).archive --db eightpi_db
docker compose cp mongo:/data/db/backup-*.archive ./
```

### Upgrade
```bash
git pull
docker compose up -d --build
```
Data volume `mongo_data` is preserved across rebuilds. Backend + frontend containers are recreated.

### Rotate JWT_SECRET
Edit `.env` → new JWT_SECRET → `docker compose restart backend`. All existing sessions become invalid; users re-login.

---

## Troubleshooting

- **`docker compose up` fails with `bind: address already in use`** — port 80 is taken. Set `HTTP_PORT=8080` in `.env` and reach the app on `http://<ip>:8080`.
- **Login returns 401 immediately** — check the backend log: `SEED_ADMIN_EMAIL` may have been rejected by the email validator (reserved TLDs like `.local`, `.internal` are refused). Use a real TLD (`.io`, `.com`, `.dev`).
- **Attack Path SSE never streams** — nginx buffering. Confirm `frontend/nginx.conf` has `proxy_buffering off` in the `/api/` block (it does by default).
- **Tools always report `mode: sim`** — the CLI binaries aren't installed. Check `curl -H "Authorization: Bearer $TOK" .../api/tools/availability`. The Dockerfile installs `nmap gobuster sqlmap nikto wpscan wapiti dirb` — rebuild the backend image if you've customised it.
- **Real scans time out** — increase timeouts via env: `docker compose exec backend env | grep TOOL`. Adjust `TIMEOUTS` in `backend/real_tools.py` and rebuild.

---

## Security notes

- The frontend is same-origin with the backend via nginx. Cookies are `httponly + secure + samesite=lax`.
- The JWT secret and admin password live only in `.env` on the host. Do NOT commit them.
- Real security-tool execution is scoped to whatever `estate.seeds` you sign in the RoE. Out-of-scope targets are refused server-side (SEC-02).
- You are responsible for authorised targets. 8pi refuses to scan targets not present in the signed RoE, but you still need written authorisation from the target owner.
