# Expected findings:
#  - ROB-AWS-S3-001 MEDIUM — legacy inline versioning { enabled = false }

resource "aws_s3_bucket" "data" {
  bucket = "my-legacy-bucket"

  versioning {
    enabled = false
  }
}
