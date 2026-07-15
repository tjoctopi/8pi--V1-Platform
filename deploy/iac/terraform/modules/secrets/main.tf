# secrets — create Secrets Manager secrets from a name->value map.
# Iterate over the (non-sensitive) key names; values are looked up per key so
# the sensitive map is never used directly as a for_each argument.
locals {
  secret_names = nonsensitive(keys(var.secrets))
}

resource "aws_secretsmanager_secret" "this" {
  for_each                = toset(local.secret_names)
  name                    = "${var.name_prefix}/${each.key}"
  recovery_window_in_days = var.recovery_window_days
  tags                    = var.tags
}

resource "aws_secretsmanager_secret_version" "this" {
  for_each      = toset(local.secret_names)
  secret_id     = aws_secretsmanager_secret.this[each.key].id
  secret_string = var.secrets[each.key]
}
