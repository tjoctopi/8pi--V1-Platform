variable "aws_region" {
  description = "AWS region. HARD-LOCKED to us-east-1 for this project."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = var.aws_region == "us-east-1"
    error_message = "This project is restricted to us-east-1 only. No other region may be touched."
  }
}

variable "project" {
  type    = string
  default = "8pi"
}

variable "env" {
  type    = string
  default = "engine-dev"
}

variable "instance_type" {
  description = "Engine host size. Runs Mongo + Postgres + Redis + Neo4j + range + tool containers."
  type        = string
  default     = "t3.xlarge"
}

variable "root_volume_gb" {
  type    = number
  default = 80
}

variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "public_subnet_cidr" {
  type    = string
  default = "10.20.1.0/24"
}

variable "bedrock_model_id" {
  description = "Bedrock model / geo inference profile for the gateway."
  type        = string
  default     = "us.anthropic.claude-opus-4-8"
}

variable "seed_admin_email" {
  type    = string
  default = "admin@8pi.io"
}

variable "seed_admin_password" {
  description = "Optional. Empty = a strong random password is generated and stored in Secrets Manager."
  type        = string
  default     = ""
  sensitive   = true
}

variable "repo_url" {
  type    = string
  default = "https://github.com/tjoctopi/8pi--V1-Platform.git"
}

variable "branch" {
  type    = string
  default = "dev"
}

variable "tags" {
  type    = map(string)
  default = {}
}
