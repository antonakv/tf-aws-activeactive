locals {
  friendly_name_prefix = "aakulov-${random_string.friendly_name.id}"
}

provider "aws" {
  region = var.region
}

data "aws_ami" "ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  owners = ["099720109477"]
}

data "aws_iam_policy_document" "secretsmanager" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    effect    = "Allow"
    resources = [aws_secretsmanager_secret_version.tfe_license.secret_id]
    sid       = "AllowSecretsManagerSecretAccess"
  }
}

data "aws_iam_policy_document" "tfe_asg_discovery" {
  statement {
    effect = "Allow"

    actions = [
      "autoscaling:Describe*"
    ]

    resources = ["*"]
  }
}

resource "random_string" "friendly_name" {
  length  = 4
  upper   = false
  numeric = false
  special = false
}

data "aws_iam_policy_document" "instance_role" {
  statement {
    effect = "Allow"
    actions = [
      "sts:AssumeRole",
    ]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance_role" {
  name_prefix        = "${local.friendly_name_prefix}-tfe"
  assume_role_policy = data.aws_iam_policy_document.instance_role.json
}

resource "aws_iam_instance_profile" "tfe" {
  name_prefix = "${local.friendly_name_prefix}-tfe"
  role        = aws_iam_role.instance_role.name
}

resource "aws_secretsmanager_secret" "tfe_license" {
  description = "The TFE license"
}

resource "aws_secretsmanager_secret_version" "tfe_license" {
  secret_binary = filebase64(var.tfe_license_path)
  secret_id     = aws_secretsmanager_secret.tfe_license.id
}

resource "aws_iam_role_policy" "tfe_asg_discovery" {
  name   = "${local.friendly_name_prefix}-tfe-asg-discovery"
  role   = aws_iam_role.instance_role.id
  policy = data.aws_iam_policy_document.tfe_asg_discovery.json
}

resource "aws_vpc" "vpc" {
  cidr_block           = var.cidr_vpc
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "${local.friendly_name_prefix}-vpc"
  }
}

resource "aws_subnet" "subnet_private1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_subnet_private_1
  availability_zone = "eu-central-1b"
}

resource "aws_subnet" "subnet_private2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_subnet_private_2
  availability_zone = "eu-central-1c"
}

resource "aws_subnet" "subnet_public1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_subnet_public_1
  availability_zone = "eu-central-1b"
}

resource "aws_subnet" "subnet_public2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_subnet_public_2
  availability_zone = "eu-central-1c"
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = "${local.friendly_name_prefix}-vpc"
  }
}

resource "aws_eip" "ssh-jump" {
  vpc      = true
  instance = aws_instance.ssh-jump.id
  depends_on = [
    aws_internet_gateway.igw
  ]
}

resource "aws_eip" "aws-nat" {
  vpc = true
  depends_on = [
    aws_internet_gateway.igw
  ]
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.aws-nat.id
  subnet_id     = aws_subnet.subnet_public1.id
  depends_on    = [aws_internet_gateway.igw]
  tags = {
    Name = "${local.friendly_name_prefix}-nat"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.vpc.id


  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = {
    Name = "${local.friendly_name_prefix}-private"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.vpc.id


  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "${local.friendly_name_prefix}-public"
  }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.subnet_private1.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.subnet_public1.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "lb-sg" {
  vpc_id = aws_vpc.vpc.id
  name   = "${local.friendly_name_prefix}-lb-sg"
  tags = {
    Name = "${local.friendly_name_prefix}-lb-sg"
  }

  ingress {
    from_port   = 8800
    to_port     = 8800
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "internal-sg" {
  vpc_id = aws_vpc.vpc.id
  name   = "${local.friendly_name_prefix}-internal-sg"
  tags = {
    Name = "${local.friendly_name_prefix}-internal-sg"
  }

  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.lb-sg.id]
  }

  ingress {
    from_port   = 8800
    to_port     = 8800
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port       = 8800
    to_port         = 8800
    protocol        = "tcp"
    security_groups = [aws_security_group.lb-sg.id]
  }

  ingress {
    from_port = 5432
    to_port   = 5432
    protocol  = "tcp"
    self      = true
  }

  ingress {
    from_port = 9000
    to_port   = 9000
    protocol  = "tcp"
    self      = true
  }

  ingress {
    from_port = 8800
    to_port   = 8800
    protocol  = "tcp"
    self      = true
  }

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    self      = true
  }

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.public-sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "public-sg" {
  vpc_id = aws_vpc.vpc.id
  name   = "${local.friendly_name_prefix}-public-sg"
  tags = {
    Name = "${local.friendly_name_prefix}-public-sg"
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8800
    to_port     = 8800
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.vpc.id
  service_name = "com.amazonaws.eu-central-1.s3"
}

resource "aws_vpc_endpoint_route_table_association" "private-s3-endpoint" {
  route_table_id  = aws_route_table.public.id
  vpc_endpoint_id = aws_vpc_endpoint.s3.id
}

resource "aws_s3_bucket" "tfe-data" {
  bucket        = "${local.friendly_name_prefix}-tfe-data"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "tfe-data" {
  bucket = aws_s3_bucket.tfe-data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_acl" "tfe-data" {
  bucket = aws_s3_bucket.tfe-data.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "tfe-data" {
  bucket = aws_s3_bucket.tfe-data.id

  block_public_acls       = true
  block_public_policy     = true
  restrict_public_buckets = true
  ignore_public_acls      = true
}

data "aws_iam_policy_document" "tfe-data" {
  statement {
    actions = [
      "s3:GetBucketLocation",
      "s3:ListBucket",
    ]
    effect = "Allow"
    principals {
      identifiers = [aws_iam_role.instance_role.arn]
      type        = "AWS"
    }
    resources = [aws_s3_bucket.tfe-data.arn]
    sid       = "AllowS3ListBucketData"
  }

  statement {
    actions = [
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:PutObject",
    ]
    effect = "Allow"
    principals {
      identifiers = [aws_iam_role.instance_role.arn]
      type        = "AWS"
    }
    resources = ["${aws_s3_bucket.tfe-data.arn}/*"]
    sid       = "AllowS3ManagementData"
  }
}

resource "aws_s3_bucket_policy" "tfe-data" {
  bucket = aws_s3_bucket_public_access_block.tfe-data.bucket
  policy = data.aws_iam_policy_document.tfe-data.json
}

resource "random_id" "redis-password" {
  byte_length = 16
}

resource "aws_security_group" "redis" {
  name   = "${local.friendly_name_prefix}-tfe-redis"
  vpc_id = aws_vpc.vpc.id
}

resource "aws_security_group_rule" "redis-tfe-ingress" {
  security_group_id        = aws_security_group.redis.id
  type                     = "ingress"
  from_port                = 6379
  to_port                  = 6380
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.internal-sg.id
}

resource "aws_security_group_rule" "redis-tfe-egress" {
  security_group_id        = aws_security_group.redis.id
  type                     = "egress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "-1"
  source_security_group_id = aws_security_group.internal-sg.id
}

resource "aws_security_group_rule" "redis_ingress" {
  security_group_id = aws_security_group.redis.id
  type              = "ingress"
  from_port         = 6379
  to_port           = 6380
  protocol          = "tcp"
  cidr_blocks       = [var.cidr_subnet_private_1, var.cidr_subnet_private_2]
}

resource "aws_security_group_rule" "redis_egress" {
  security_group_id = aws_security_group.redis.id
  type              = "egress"
  from_port         = 6379
  to_port           = 6380
  protocol          = "tcp"
  cidr_blocks       = [var.cidr_subnet_private_1, var.cidr_subnet_private_2]
}

resource "aws_elasticache_subnet_group" "tfe" {
  name       = "${local.friendly_name_prefix}-tfe-redis"
  subnet_ids = [aws_subnet.subnet_private1.id, aws_subnet.subnet_private2.id]
}

resource "aws_elasticache_replication_group" "redis" {
  node_type                  = var.instance_type_redis
  num_cache_clusters         = 1
  replication_group_id       = "${local.friendly_name_prefix}-tfe"
  description                = "Redis replication group for TFE"
  apply_immediately          = true
  at_rest_encryption_enabled = false
  auth_token                 = random_id.redis-password.hex
  automatic_failover_enabled = false
  engine                     = "redis"
  engine_version             = "5.0.6"
  parameter_group_name       = "default.redis5.0"
  port                       = 6379
  subnet_group_name          = aws_elasticache_subnet_group.tfe.name
  transit_encryption_enabled = true
  multi_az_enabled           = false
  auto_minor_version_upgrade = true
  snapshot_retention_limit   = 0
}

resource "aws_instance" "ssh-jump" {
  ami                         = var.jump_ami
  instance_type               = var.instance_type_jump
  key_name                    = var.key_name
  vpc_security_group_ids      = [aws_security_group.public-sg.id]
  subnet_id                   = aws_subnet.subnet_public1.id
  associate_public_ip_address = true
  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 2
  }
  tags = {
    Name = "${local.friendly_name_prefix}-ssh-jump"
  }
}

