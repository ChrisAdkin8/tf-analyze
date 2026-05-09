# Crown jewels. All three reachable from the web role via the wildcard
# IAM policy in iam.tf. The attack graph traces:
#
#   internet → ALB → web EC2 → IAM profile → IAM role → {S3, Secrets, RDS}
#
# Each of these resources is in `_CROWN_JEWEL_TYPES` in detect.py.

# S3 bucket — no SSE config, no public-access block, no logging.
# Multiple findings: SEC-AWS-S3-001, SEC-AWS-S3-PUBLIC-BLOCK-001,
# SEC-AWS-S3-LOGGING-001, ROB-AWS-S3-001 (versioning).
resource "aws_s3_bucket" "appdata" {
  bucket = "${var.app_name}-data"

  tags = { Tier = "data" }
}

# Secrets Manager — no KMS, no recovery window, no rotation.
resource "aws_secretsmanager_secret" "db_password" {
  name = "${var.app_name}-db-password"

  # Anti-pattern: missing kms_key_id (defaults to AWS-managed key) and
  # missing recovery_window_in_days (defaults to immediate delete).
  recovery_window_in_days = 0
}

# RDS instance in the data subnet — also internal-only by SG, but
# reachable via the web SG ingress rule. Public-access disabled.
resource "aws_db_instance" "appdb" {
  identifier             = "${var.app_name}-db"
  engine                 = "postgres"
  engine_version         = "15.5"
  instance_class         = "db.t3.micro"
  username               = "appuser"
  password               = "changeme"
  allocated_storage      = 20
  publicly_accessible    = false
  vpc_security_group_ids = [aws_security_group.data.id]
  db_subnet_group_name   = aws_db_subnet_group.app.name
  skip_final_snapshot    = true

  # Anti-pattern: storage_encrypted not set; deletion_protection
  # missing; no kms_key_id. Multiple findings (ROB-AWS-RDS-*).
}

resource "aws_db_subnet_group" "app" {
  name       = "${var.app_name}-db-subnets"
  subnet_ids = [aws_subnet.private.id, aws_subnet.public.id]
}
