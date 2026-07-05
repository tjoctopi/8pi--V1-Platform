variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "env" {
  description = "Environment tag (dev / staging / prod)."
  type        = string
  default     = "prod"
}

variable "instance_type" {
  description = "EC2 instance size. t3.medium is the recommended minimum."
  type        = string
  default     = "t3.medium"
}

variable "root_volume_gb" {
  description = "Root EBS volume size in GB."
  type        = number
  default     = 30
}

variable "ssh_cidrs" {
  description = "CIDR list allowed to SSH (port 22). Restrict to your operator IP(s)."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "ssh_public_key" {
  description = "OpenSSH public key content. Leave empty to auto-generate a keypair (private key is written next to main.tf)."
  type        = string
  default     = ""
}

# ──────────────── application ────────────────
variable "repo_url" {
  description = "Public git URL of your 8pi fork (e.g. https://github.com/you/8pi.git)."
  type        = string
}

variable "branch" {
  description = "Git branch to check out."
  type        = string
  default     = "main"
}

variable "domain" {
  description = "Fully-qualified domain that will point at the EC2's Elastic IP. Empty = serve on the raw IP (no TLS). For the 8π console use `app.8pi.ai`; the marketing site at `8pi.ai` is deployed separately."
  type        = string
  default     = ""
}

variable "tls_email" {
  description = "Email used for Let's Encrypt registration (only used if `domain` is set)."
  type        = string
  default     = ""
}

variable "admin_email" {
  description = "Operator email for alerting / notes (not used by the app itself)."
  type        = string
  default     = ""
}

# ──────────────── secrets injected into the app ────────────────
variable "seed_admin_email" {
  description = "Admin account email seeded on first boot."
  type        = string
}

variable "seed_admin_password" {
  description = "Admin password seeded on first boot (MIN 8 chars, change immediately after first login)."
  type        = string
  sensitive   = true
}

variable "jwt_secret" {
  description = "64-char hex JWT signing secret. Generate: python -c \"import secrets; print(secrets.token_hex(32))\""
  type        = string
  sensitive   = true
}

variable "bedrock_model_id" {
  description = "Amazon Bedrock model ID / geo inference profile for the Model Gateway. Default = Claude Opus 4.8 (US geo profile). EU: eu.anthropic.claude-opus-4-8, global: global.anthropic.claude-opus-4-8."
  type        = string
  default     = "us.anthropic.claude-opus-4-8"
}

variable "tool_mode" {
  description = "auto | real | sim. Real = call CLI binaries (nmap etc); auto = real if installed, sim fallback."
  type        = string
  default     = "auto"
}

variable "tags" {
  description = "Additional AWS tags."
  type        = map(string)
  default     = {}
}
