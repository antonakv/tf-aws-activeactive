variable "region" {
  type        = string
  description = "AWS region"
}
variable "tfe_license_path" {
  type        = string
  description = "Path for the TFE license"
}
variable "cidr_vpc" {
  type        = string
  description = "Amazon EC2 VPC net"
}
variable "cidr_subnet_private_1" {
  type        = string
  description = "Amazon EC2 subnet 1 private"
}
variable "cidr_subnet_private_2" {
  type        = string
  description = "Amazon EC2 subnet 2 private"
}
variable "cidr_subnet_public_1" {
  type        = string
  description = "Amazon EC2 subnet 1 public"
}
variable "cidr_subnet_public_2" {
  type        = string
  description = "Amazon EC2 subnet 2 public"
}
variable "instance_type_redis" {
  description = "Amazon Elasticashe Redis instance type"
}
variable "instance_type_jump" {
  description = "Ssh jump instance type"
}
variable "jump_ami" {
  description = "Amazon EC2 ami created with Packer"
}
variable "key_name" {
  description = "Name of Amazon EC2 keypair for the specific region"
}
variable "db_instance_type" {
  description = "Amazon EC2 RDS instance type"
}
variable "instance_type" {
  description = "Amazon EC2 instance type"
}
variable "tfe_hostname" {
  type        = string
  description = "Terraform Enterprise hostname"
}
variable "tfe_hostname_jump" {
  type        = string
  description = "Terraform Enterprise jump hostname"
}
variable "domain_name" {
  type        = string
  description = "Domain name"
}
variable "release_sequence" {
  type        = number
  description = "Terraform Enterprise release sequence number"
}
variable "postgres_db_name" {
  type        = string
  description = "Postgres database DB name"
}
variable "postgres_engine_version" {
  type        = string
  description = "Postgres engine version"
}
variable "postgres_username" {
  type        = string
  description = "Postgres database username"
}
variable "aws_ami" {
  type        = string
  description = "Ubuntu focal AMI with preinstalled docker-ce 20.10.7 docker-ce-cli 20.10.7 containerd.io"
}
variable "asg_min_nodes" {
  type        = number
  description = "Minimal number of nodes in Autoscaling group"
  validation {
    condition     = var.asg_min_nodes >= 2
    error_message = "Minimal number of nodes for ActiveActive is >= 2"
  }
}
variable "asg_max_nodes" {
  type        = number
  default     = 2
  description = "Maximal number of nodes in Autoscaling group"
}
variable "asg_desired_nodes" {
  type        = number
  description = "Desired number of nodes in Autoscaling group"
  validation {
    condition     = var.asg_desired_nodes <= 3
    error_message = "Maximal number of active nodes for ActiveActive is 3"
  }
}
variable "cloudflare_zone_id" {
  type        = string
  description = "Cloudflare DNS zone id"
}
variable "cloudflare_api_token" {
  type        = string
  description = "Cloudflare DNS API token"
}
variable "ssl_cert_path" {
  type        = string
  description = "SSL certificate file path"
}
variable "ssl_fullchain_cert_path" {
  type        = string
  description = "SSL fullchain cert file path"
}
variable "ssl_key_path" {
  type        = string
  description = "SSL key file path"
}
variable "ssl_chain_path" {
  type        = string
  description = "SSL chain file path"
}
variable "lb_ssl_policy" {
  type        = string
  description = "SSL policy for load balancer"
}
