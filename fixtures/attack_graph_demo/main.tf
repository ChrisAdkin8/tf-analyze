# Multi-resource attack path demo fixture.
# Demonstrates: internet-reachable EC2 → IAM profile → role → S3 crown jewel.
# Expected findings are determined by running detect.py and listed in catalogue
# fixtures: fields for each rule that fires here.

terraform {
  required_version = ">= 1.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
  }
}

# Public EC2 instance — internet-reachable, IMDSv1 enabled (no metadata_options)
resource "aws_instance" "web" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.web_profile.name
  vpc_security_group_ids      = [aws_security_group.open.id]

  tags = { Name = "attack-graph-demo" }
}

# Security group open to the internet on port 80 (SEC-AWS-SG-001)
resource "aws_security_group" "open" {
  name        = "open-sg"
  description = "Demo open security group"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "open-sg" }
}

# IAM instance profile → role (attack path link)
resource "aws_iam_instance_profile" "web_profile" {
  name = "web-profile"
  role = aws_iam_role.web_role.name
  tags = { Name = "web-profile" }
}

resource "aws_iam_role" "web_role" {
  name = "web-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Name = "web-role" }
}

# IAM policy with wildcard resource — SEC-AWS-IAM-001
data "aws_iam_policy_document" "broad" {
  statement {
    actions   = ["s3:*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "broad" {
  name   = "broad-policy"
  policy = data.aws_iam_policy_document.broad.json
  tags   = { Name = "broad-policy" }
}

# S3 bucket (crown jewel) — no server-side encryption resource (SEC-AWS-S3-001)
resource "aws_s3_bucket" "data" {
  bucket = "attack-graph-demo-data"

  tags = { Name = "attack-graph-demo-data" }
}

# KMS key (crown jewel) — no key rotation (SEC-AWS-KMS-001)
resource "aws_kms_key" "data_key" {
  description = "Demo data key"
  tags        = { Name = "data-key" }
}
