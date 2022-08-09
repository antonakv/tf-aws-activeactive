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
