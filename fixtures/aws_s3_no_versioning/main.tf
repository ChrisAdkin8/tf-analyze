# Expected findings:
#  - ROB-AWS-S3-001 MEDIUM — S3 bucket versioning disabled or suspended

resource "aws_s3_bucket" "data" {
  bucket = "my-unversioned-bucket"
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id

  versioning_configuration {
    status = "Suspended"
  }
}
