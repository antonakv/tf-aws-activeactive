output "aws_jump_hostname" {
  value       = cloudflare_record.tfe_jump.name
  description = "SSH jump hostname"
}
output "aws_jump_public_ip" {
  value       = aws_instance.ssh_jump.public_ip
  description = "SSH jump public ip"
}
output "url" {
  value       = "https://${local.tfe_hostname}/admin/account/new?token=${random_id.user_token.hex}"
  description = "Login URL and token"
}
output "ssh_key_name" {
  value       = var.key_name
  description = "SSH key name"
}
output "aws_lb_active_target_group_hosts" {
  value       = join(", ", data.aws_instances.tfe.private_ips)
  description = "EC2 hosts in the AWS LB target group"
}
