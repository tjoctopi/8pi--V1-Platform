variable "name" {
  type = string
}

variable "assume_service" {
  type    = string
  default = "ec2.amazonaws.com"
}

variable "managed_policy_arns" {
  description = "Managed policy ARNs to attach (e.g. AmazonSSMManagedInstanceCore)."
  type        = list(string)
  default     = []
}

variable "inline_policy_json" {
  description = "Inline policy document JSON (used only when attach_inline_policy = true)."
  type        = string
  default     = ""
}

variable "attach_inline_policy" {
  description = "Whether to attach the inline policy. Static boolean so count is known at plan time."
  type        = bool
  default     = false
}

variable "tags" {
  type    = map(string)
  default = {}
}
