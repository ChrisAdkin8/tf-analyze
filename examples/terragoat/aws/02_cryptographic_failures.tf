# OWASP A02:2021 — Cryptographic Failures
# Cloud: AWS
#
# Six common AWS cryptographic failure modes:
#
#   1. S3 bucket without `server_side_encryption_configuration` —
#      objects land in cleartext (well, at-rest with the AWS-owned
#      key, but no audit trail of the KEK and no separation between
#      tenants).
#   2. RDS instance with `storage_encrypted = false` — disk is plain
#      EBS without KMS. Forensic recovery from a snapshot leaves a
#      decrypted backup.
#   3. EBS volume without `encrypted = true` — same shape as RDS.
#   4. KMS key without `enable_key_rotation = true` — annual
#      rotation is the AWS default but must be opted into per key.
#   5. ALB / API Gateway with HTTP listener and no HTTPS redirect —
#      cleartext credentials cross the network.
#
# Real-world impact:
#   - Unencrypted snapshots are routinely shared cross-account by
#     mistake; with encryption + per-key IAM, the snapshot is
#     unreadable even if shared.
#   - HTTP listeners enable opportunistic credential harvesting on
#     coffee-shop wifi.
#
# Expected tf-analyze findings:
#   - SEC-AWS-S3-001    HIGH  S3 bucket missing server-side encryption
#   - SEC-AWS-RDS-002   HIGH  RDS instance storage not encrypted
#   - SEC-AWS-KMS-001   HIGH  KMS key rotation disabled
#   - SEC-AWS-EBS-001   HIGH  EBS volume not encrypted
#   - STK-AWS-RDS-004   HIGH  RDS running end-of-life engine version
#
# Fix summary: turn on every encryption flag explicitly; never rely
# on AWS account defaults (they vary by region and by account age).

# S3 bucket without SSE config block.
resource "aws_s3_bucket" "no_sse" {
  bucket = "demo-no-sse"
}

# RDS without storage encryption.
resource "aws_db_instance" "unencrypted" {
  identifier            = "demo-unencrypted"
  engine                = "postgres"
  engine_version        = "15.6"
  instance_class        = "db.t3.micro"
  allocated_storage     = 20
  username              = "postgres"
  password              = "tempPASSWORD123!" # also a credential leak — see 04
  storage_encrypted     = false              # unencrypted disk
  skip_final_snapshot   = true
  deletion_protection   = false
}

# EBS volume without encryption.
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false
}

# KMS key with rotation off.
resource "aws_kms_key" "no_rotation" {
  description             = "demo key, rotation off"
  deletion_window_in_days = 7
  enable_key_rotation     = false
}

# RDS on a MySQL 5.6 EOL engine version.
resource "aws_db_instance" "eol_engine" {
  identifier          = "demo-eol-engine"
  engine              = "mysql"
  engine_version      = "5.6.51"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = "tempPASSWORD123!"
  skip_final_snapshot = true
}
