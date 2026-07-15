variable "name_prefix" {
  description = "Path prefix for secret names, e.g. /8pi-engine-dev."
  type        = string
}

variable "secrets" {
  description = "Map of secret short-name => value."
  type        = map(string)
  sensitive   = true
}

variable "recovery_window_days" {
  description = "Deletion recovery window (0 = force delete, use in dev)."
  type        = number
  default     = 7
}

variable "tags" {
  type    = map(string)
  default = {}
}
