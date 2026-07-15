# Ansible — 8pi attack-engine config + deployment

Configures the Terraform-provisioned host and deploys the databases, the range,
and the console+engine stack. Connects over **SSM Session Manager** (no SSH).

## Roles (modular)
| Role | Does |
|------|------|
| `common` | base packages, repo checkout, renders `.env` from Secrets Manager (keyless, on host) |
| `docker` | Docker Engine + Compose plugin, creates the shared `8pi_data_net` |
| `databases` | Postgres + Redis + Neo4j on `8pi_data_net` |
| `range` | intentionally-vulnerable range; creates `attack-engine-range_range_net` |
| `engine` | console + attack-engine stack (AE_* wiring, docker.sock, joins both nets) |
| `verify` | health checks (HTTP, Postgres, Redis, Neo4j) |

## Prerequisites (controller)
- Terraform infra applied (host tagged `Project=8pi`, `Env=engine-dev`).
- AWS CLI + `session-manager-plugin` installed; credentials for us-east-1.
- Collections: `ansible-galaxy collection install -r requirements.yml`
- An S3 bucket in us-east-1 for SSM file transfer (the Terraform backups bucket works).

## Run
```bash
cd deploy/iac/ansible
ansible-galaxy collection install -r requirements.yml

# syntax check only (no host contact)
ansible-playbook site.yml --syntax-check

# full deploy (only after explicit go)
ansible-playbook site.yml -e ssm_transfer_bucket=<backups-bucket>

# a single layer, e.g. just the databases
ansible-playbook site.yml --tags databases -e ssm_transfer_bucket=<bucket>
```

## Notes
- Secrets are fetched on the host via the instance role and written to `{{ app_dir }}/.env` (mode 0600); they never pass through the controller or Ansible logs (`no_log`).
- Model gateway is keyless Bedrock (`AE_MODEL_FRONTIER=bedrock/us.anthropic.claude-opus-4-8`) resolved through the instance role.
- Nothing is exposed publicly; reach the console with an SSM port-forward to `127.0.0.1:{{ http_port }}`.
