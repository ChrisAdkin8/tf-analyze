# Auto-generated clean fixture for ROB-AWS-S3-001.
# S3 bucket versioning disabled or suspended
# This is a CORRECT configuration; ROB-AWS-S3-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration {
    status = "Enabled"
  }
}
