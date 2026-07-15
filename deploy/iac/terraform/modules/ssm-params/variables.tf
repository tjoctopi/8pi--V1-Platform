variable "prefix" {
  description = "Path prefix, e.g. /8pi-engine-dev."
  type        = string
}

variable "parameters" {
  description = "Map of short-name => value (non-secret config only)."
  type        = map(string)
  default     = {}
}

variable "tier" {
  type    = string
  default = "Standard"
}

variable "tags" {
  type    = map(string)
  default = {}
}
