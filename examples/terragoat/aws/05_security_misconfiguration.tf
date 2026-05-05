# OWASP A05:2021 — Security Misconfiguration
# Cloud: AWS
#
# The largest OWASP category by volume. AWS-specific shapes:
#
#   1. Security group with `0.0.0.0/0` ingress on sensitive ports
#      (22, 3389, 1433, 3306, 5432, 6379, 9200…). World-open SSH /
#      RDP / SQL is the most-attacked attack surface on AWS.
#   2. EC2 instance with `associate_public_ip_address = true` in a
#      public subnet — same exposure shape as GCP `access_config`.
#   3. RDS publicly accessible (`publicly_accessible = true`).
#   4. Lambda without a `tracing_config` block — silent on errors.
#   5. CloudFront distribution with `viewer_protocol_policy = "allow-all"`
#      — HTTP requests served without redirect.
#
# Expected tf-analyze findings:
#   - SEC-AWS-SG-001   HIGH   Security group allows ingress from 0.0.0.0/0
#
# Fix summary: every SG ingress rule needs a CIDR or a security-
# group reference, never `0.0.0.0/0` for sensitive ports. Public IPs
# only on bastion hosts behind SSM Session Manager. RDS publicly
# accessible only with a strong, audited business reason.

# SG with world-open SSH — fires SEC-AWS-SG-001.
resource "aws_security_group" "ssh_open" {
  name        = "demo-ssh-open"
  description = "SSH open to the world"
  vpc_id      = "vpc-12345678"

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

# EC2 with public IP in a public subnet.
resource "aws_instance" "public" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.micro"
  subnet_id                   = "subnet-12345678"
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.ssh_open.id]
}

# RDS publicly accessible.
resource "aws_db_instance" "public_db" {
  identifier            = "demo-public-db"
  engine                = "postgres"
  engine_version        = "15.6"
  instance_class        = "db.t3.micro"
  allocated_storage     = 20
  username              = "postgres"
  password              = var.db_password
  publicly_accessible   = true
  storage_encrypted     = true
  skip_final_snapshot   = true
  deletion_protection   = true
}

variable "db_password" {
  description = "Database master password"
  type        = string
  sensitive   = true
}
