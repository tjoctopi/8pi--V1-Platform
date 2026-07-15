# engine-dev — Terraform environment

Provisions the isolated AWS infrastructure for the 8pi attack-engine dev/test host in **us-east-1 only**.
Configuration and application deployment are handled separately by Ansible (`../../ansible`).

## What it creates
- Isolated VPC + public subnet + IGW (`network`)
- Security group with **no inbound** (access is via SSM Session Manager); egress open for image pulls + AWS APIs (`security-group`)
- EC2 host (Ubuntu 22.04, IMDSv2, encrypted gp3, EIP) — **no SSH key** (`ec2-host`)
- IAM instance role: keyless Bedrock invoke + SSM core + scoped Secrets/SSM reads + S3 backups + ECR pull (`iam-role`)
- Secrets Manager: `jwt-secret`, `seed-admin-password`, `postgres-password`, `neo4j-password` (random-generated) (`secrets`)
- SSM Parameter Store: non-secret config for Ansible (`ssm-params`)
- Private encrypted versioned S3 backups bucket (`s3-backups`)

## Usage
```bash
cd deploy/iac/terraform/envs/engine-dev

# validate only (no cloud calls)
terraform init -backend=false
terraform fmt -recursive ../..
terraform validate

# real init against remote state (reuses the existing 8pi state bucket; own key)
cp backend.hcl.example backend.hcl   # fill bucket + lock table
terraform init -backend-config=backend.hcl

cp terraform.tfvars.example terraform.tfvars
terraform plan      # review
terraform apply     # only after explicit go
```

## Guardrails
- `aws_region` is validated to equal `us-east-1`; any other value fails at plan time.
- State key is fixed to `engine-dev/terraform.tfstate`, isolated from the console env in the same bucket.
- No secret values live in tfvars: passwords are generated and stored in Secrets Manager.

## Teardown
`terraform destroy` removes only this env (own state key + own VPC); the console env is untouched.
