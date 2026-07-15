# ssm-params — non-secret config for the host/Ansible to read at deploy time.
resource "aws_ssm_parameter" "this" {
  for_each = var.parameters
  name     = "${var.prefix}/${each.key}"
  type     = "String"
  value    = each.value
  tier     = var.tier
  tags     = var.tags
}
