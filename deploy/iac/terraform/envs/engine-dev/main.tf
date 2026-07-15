locals {
  name = "${var.project}-${var.env}" # 8pi-engine-dev
  tags = merge(var.tags, {
    Project = var.project
    Env     = var.env
    Managed = "terraform"
  })
}

data "aws_caller_identity" "me" {}

# ──────────────── network (isolated VPC) ────────────────
module "network" {
  source             = "../../modules/network"
  name               = local.name
  vpc_cidr           = var.vpc_cidr
  public_subnet_cidr = var.public_subnet_cidr
  tags               = local.tags
}

# ──────────────── security group (no inbound; SSM-only) ────────────────
module "security_group" {
  source        = "../../modules/security-group"
  name          = local.name
  vpc_id        = module.network.vpc_id
  description   = "8pi engine host: no inbound (SSM Session Manager only); egress for image pulls + AWS APIs"
  ingress_rules = [] # SSM-only, nothing exposed
  # egress uses the module default (all outbound). Tighten to VPC endpoints later.
  tags = local.tags
}

# ──────────────── generated secrets → Secrets Manager ────────────────
resource "random_password" "jwt" {
  length  = 64
  special = false
}

resource "random_password" "postgres" {
  length  = 24
  special = false
}

resource "random_password" "neo4j" {
  length  = 24
  special = false
}

resource "random_password" "admin" {
  length  = 20
  special = false
}

module "secrets" {
  source      = "../../modules/secrets"
  name_prefix = "/${local.name}"
  secrets = {
    "jwt-secret"          = random_password.jwt.result
    "seed-admin-password" = var.seed_admin_password != "" ? var.seed_admin_password : random_password.admin.result
    "postgres-password"   = random_password.postgres.result
    "neo4j-password"      = random_password.neo4j.result
  }
  recovery_window_days = 0 # dev: allow immediate delete/recreate
  tags                 = local.tags
}

# ──────────────── S3 backups bucket ────────────────
module "backups" {
  source        = "../../modules/s3-backups"
  bucket_name   = "${local.name}-backups-${data.aws_caller_identity.me.account_id}"
  force_destroy = true # dev
  tags          = local.tags
}

# ──────────────── IAM instance role (keyless Bedrock + SSM + scoped reads) ────────────────
data "aws_iam_policy_document" "app" {
  statement {
    sid       = "BedrockInvoke"
    actions   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
    resources = ["*"]
  }
  statement {
    sid       = "SecretsRead"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = ["arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.me.account_id}:secret:/${local.name}/*"]
  }
  statement {
    sid       = "SSMParamsRead"
    actions   = ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"]
    resources = ["arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.me.account_id}:parameter/${local.name}/*"]
  }
  statement {
    sid       = "S3Backups"
    actions   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
    resources = [module.backups.bucket_arn, "${module.backups.bucket_arn}/*"]
  }
  statement {
    sid       = "ECRPull"
    actions   = ["ecr:GetAuthorizationToken", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"]
    resources = ["*"]
  }
}

module "iam" {
  source               = "../../modules/iam-role"
  name                 = local.name
  managed_policy_arns  = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]
  inline_policy_json   = data.aws_iam_policy_document.app.json
  attach_inline_policy = true
  tags                 = local.tags
}

# ──────────────── EC2 host ────────────────
module "ec2" {
  source               = "../../modules/ec2-host"
  name                 = local.name
  instance_type        = var.instance_type
  subnet_id            = module.network.public_subnet_id
  security_group_ids   = [module.security_group.security_group_id]
  iam_instance_profile = module.iam.instance_profile_name
  root_volume_gb       = var.root_volume_gb
  tags                 = local.tags
}

# ──────────────── non-secret config for Ansible (SSM Parameter Store) ────────────────
module "config" {
  source = "../../modules/ssm-params"
  prefix = "/${local.name}"
  parameters = {
    "aws-region"       = var.aws_region
    "bedrock-model-id" = var.bedrock_model_id
    "model-frontier"   = "bedrock/${var.bedrock_model_id}"
    "range-network"    = "attack-engine-range_range_net"
    "seed-admin-email" = var.seed_admin_email
    "repo-url"         = var.repo_url
    "branch"           = var.branch
    "secrets-prefix"   = "/${local.name}"
    "backups-bucket"   = module.backups.bucket_name
  }
  tags = local.tags
}
