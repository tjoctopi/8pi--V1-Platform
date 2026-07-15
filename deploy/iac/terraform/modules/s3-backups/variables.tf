variable "bucket_name" {
  type = string
}

variable "force_destroy" {
  description = "Allow deleting a non-empty bucket (dev convenience)."
  type        = bool
  default     = false
}

variable "tags" {
  type    = map(string)
  default = {}
}
