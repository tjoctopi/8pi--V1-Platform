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
  description = "EC2 instance size. The tool executor is CPU/network-heavy; t3.large is the recommended minimum."
  type        = string
  default     = "t3.large"
}

variable "root_volume_gb" {
  description = "Root EBS volume size in GB (tool images are large — budget headroom)."
  type        = number
  default     = 40
}

variable "ssh_cidrs" {
  description = "CIDR list allowed to SSH (port 22). Restrict to your operator IP(s). (SSM Session Manager is also enabled and needs no inbound SSH.)"
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
  description = "Git branch to check out. The real engine lives on `dev` (main is the legacy prototype); use `dev` or a release branch."
  type        = string
  default     = "dev"
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

# ──────────────── secrets / config injected into the engine ────────────────
variable "ae_api_admin_email" {
  description = "Admin account email seeded on first boot (AE_API_ADMIN_EMAIL)."
  type        = string
}

variable "ae_api_admin_password" {
  description = "Admin password seeded on first boot (AE_API_ADMIN_PASSWORD; change after first login)."
  type        = string
  sensitive   = true
}

variable "ae_api_jwt_secret" {
  description = "64-char hex JWT signing secret (AE_API_JWT_SECRET). Generate: python -c \"import secrets; print(secrets.token_hex(32))\""
  type        = string
  sensitive   = true
}

# ──────────────── BYOM model gateway (set at least one, or ae_model_mock=true) ────────────────
variable "fireworks_api_key" {
  description = "Fireworks AI API key (FIREWORKS_API_KEY) for the BYOM model gateway."
  type        = string
  default     = ""
  sensitive   = true
}

variable "anthropic_api_key" {
  description = "Anthropic API key (ANTHROPIC_API_KEY) for the frontier tier via the BYOM gateway."
  type        = string
  default     = ""
  sensitive   = true
}

variable "ae_model_mock" {
  description = "When true, the model gateway uses a deterministic mock (no real reasoning). For keyless smoke tests only."
  type        = bool
  default     = false
}

variable "ae_sandbox_network" {
  description = "Docker network the sandboxed tool containers join so they can reach the authorized targets. Created on the host at boot."
  type        = string
  default     = "ae_targets"
}

variable "tags" {
  description = "Additional AWS tags."
  type        = map(string)
  default     = {}
}
