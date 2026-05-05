# OWASP A08:2021 — Software and Data Integrity Failures
# Cloud: AWS
#
# Three AWS-shaped integrity failures:
#
#   1. S3 bucket without versioning. An accidental `aws s3 rm` or
#      `terraform destroy` is unrecoverable. Same shape as GCS,
#      different API.
#   2. S3 bucket without Object Lock for compliance / immutability
#      use cases. Important for log buckets used in regulated
#      environments.
#   3. RDS / Aurora without `backup_retention_period` set, or set to
#      0. AWS keeps no backups by default; a single failure is
#      total data loss.
#   4. ECR repository without image scanning enabled — supply chain
#      attacks via compromised base images go unnoticed.
#
# Real-world impact:
#   - Many incidents involve accidental S3 object deletion that
#     versioning would have made recoverable.
#   - Compromised base images (Docker Hub library/* takeovers, etc.)
#     ship to production without ECR scanning.
#
# Expected tf-analyze findings:
#   - (no AWS-specific catalogue rule fires here today; documented
#    as roadmap)
#
# Fix summary: turn on versioning + a lifecycle rule that expires
# non-current versions after N days; set
# `backup_retention_period = 7` (or longer) on every database; turn
# on `image_scanning_configuration.scan_on_push` on every ECR repo.

# S3 bucket without versioning.
resource "aws_s3_bucket" "no_versioning" {
  bucket = "demo-no-versioning"
}

# (Note: aws_s3_bucket_versioning is a separate resource since
# provider v4. Its absence is the integrity failure.)

# RDS with backups disabled.
resource "aws_db_instance" "no_backups" {
  identifier              = "demo-no-backups"
  engine                  = "postgres"
  engine_version          = "15.6"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  username                = "postgres"
  password                = "ZeroBackupsHere!"
  backup_retention_period = 0 # disables backups
  storage_encrypted       = true
  skip_final_snapshot     = true
  deletion_protection     = true
}

# ECR repository without image scanning.
resource "aws_ecr_repository" "unscanned" {
  name = "demo-unscanned"
  # image_scanning_configuration { scan_on_push = true } intentionally
  # omitted — supply-chain CVEs ship to production silently.
}
