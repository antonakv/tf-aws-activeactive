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
variable "cidr_subnet1" {
  type        = string
  description = "Amazon EC2 subnet 1"
}
variable "cidr_subnet2" {
  type        = string
  description = "Amazon EC2 subnet 2"
}
variable "cidr_subnet3" {
  type        = string
  description = "Amazon EC2 subnet 3"
}
variable "cidr_subnet4" {
  type        = string
  description = "Amazon EC2 subnet 4"
}
