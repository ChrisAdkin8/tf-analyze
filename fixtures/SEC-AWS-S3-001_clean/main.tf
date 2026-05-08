# Auto-generated clean fixture for SEC-AWS-S3-001.
# S3 bucket missing server-side encryption configuration
# This is a CORRECT configuration; SEC-AWS-S3-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
