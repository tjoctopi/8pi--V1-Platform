output "instance_id" {
  value = aws_instance.this.id
}

output "private_ip" {
  value = aws_instance.this.private_ip
}

output "public_ip" {
  value = var.associate_eip ? aws_eip.this[0].public_ip : aws_instance.this.public_ip
}
