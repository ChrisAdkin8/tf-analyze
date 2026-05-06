# Expected findings: SEC-AWS-S3-LOGGING-001

resource "aws_s3_bucket" "app" {
  bucket = "demo-app-data"
}

# No aws_s3_bucket_logging resource — SEC-AWS-S3-LOGGING-001 fires.
