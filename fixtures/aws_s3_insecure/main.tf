# Expected findings:
#  - SEC-AWS-S3-001 HIGH — S3 bucket without encryption configuration

resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}

# No aws_s3_bucket_server_side_encryption_configuration resource exists
