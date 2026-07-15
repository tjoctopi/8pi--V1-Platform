variable "name" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "description" {
  type    = string
  default = "Managed by terraform"
}

variable "ingress_rules" {
  description = "Ingress rules. Default empty = no inbound (SSM-only access)."
  type = list(object({
    description = string
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
  }))
  default = []
}

variable "egress_rules" {
  description = "Egress rules. Default = all outbound (needed for image pulls + AWS APIs)."
  type = list(object({
    description = string
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
  }))
  default = [{
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }]
}

variable "tags" {
  type    = map(string)
  default = {}
}
