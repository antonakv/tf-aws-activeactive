output "aws_jump" {
  value = cloudflare_record.tfe_jump.name
  description = "SSH jump host"
}
output "url" {
  value       = "https://${local.tfe_hostname}/admin/account/new?token=${random_id.user_token.hex}"
  description = "Login URL and token"
}
output "ssh_key_name" {
  value = var.key_name
  description = "SSH key name"
}
