output "instance_id" {
  description = "EC2 instance id (target for Ansible over SSM)."
  value       = module.ec2.instance_id
}

output "public_ip" {
  value = module.ec2.public_ip
}

output "private_ip" {
  value = module.ec2.private_ip
}

output "vpc_id" {
  value = module.network.vpc_id
}

output "secrets_prefix" {
  value = module.secrets.name_prefix
}

output "backups_bucket" {
  value = module.backups.bucket_name
}

output "ssm_config_prefix" {
  value = module.config.prefix
}
