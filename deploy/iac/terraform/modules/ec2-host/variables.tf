variable "name" {
  type = string
}

variable "ami_id" {
  description = "AMI ID. Empty = latest Ubuntu 22.04 LTS (Canonical)."
  type        = string
  default     = ""
}

variable "instance_type" {
  description = "EC2 instance size. Engine + range need headroom; t3.xlarge minimum."
  type        = string
  default     = "t3.xlarge"
}

variable "subnet_id" {
  type = string
}

variable "security_group_ids" {
  type = list(string)
}

variable "iam_instance_profile" {
  type = string
}

variable "root_volume_gb" {
  type    = number
  default = 80
}

variable "user_data" {
  description = "Optional cloud-init. Empty = none (config is done by Ansible over SSM)."
  type        = string
  default     = ""
}

variable "associate_eip" {
  type    = bool
  default = true
}

variable "tags" {
  type    = map(string)
  default = {}
}
