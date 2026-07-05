output "instance_id" {
  description = "EC2 instance ID."
  value       = aws_instance.app.id
}

output "public_ip" {
  description = "Elastic IP address of the app."
  value       = aws_eip.app.public_ip
}

output "public_dns" {
  description = "Public DNS name from AWS."
  value       = aws_instance.app.public_dns
}

output "app_url" {
  description = "URL to open in the browser once bootstrap completes (~4 min)."
  value       = var.domain != "" ? "https://${var.domain}" : "http://${aws_eip.app.public_ip}"
}

output "ssh_command" {
  description = "Copy-paste to SSH in."
  value = var.ssh_public_key == "" ? (
    "ssh -i ${path.module}/8pi-${var.env}.pem ubuntu@${aws_eip.app.public_ip}"
    ) : (
    "ssh -i <your-private-key> ubuntu@${aws_eip.app.public_ip}"
  )
}

output "bootstrap_log_hint" {
  description = "Tail the cloud-init log to watch the stack come up."
  value       = "ssh in and run: sudo tail -f /var/log/8pi-bootstrap.log"
}
