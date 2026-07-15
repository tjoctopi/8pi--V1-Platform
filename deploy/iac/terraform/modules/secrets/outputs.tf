output "secret_arns" {
  description = "Map of short-name => secret ARN."
  value       = { for k, s in aws_secretsmanager_secret.this : k => s.arn }
}

output "name_prefix" {
  value = var.name_prefix
}
