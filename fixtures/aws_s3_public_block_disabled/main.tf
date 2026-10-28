# Expected findings:
#  - SEC-AWS-S3-PUBLIC-BLOCK-001 HIGH — public access block with flags false or left out
#  - SEC-AWS-S3-PUBLIC-BLOCK-001 HIGH — account-level public access block switched off

resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket              = aws_s3_bucket.data.id
  block_public_acls   = false
  block_public_policy = true
  # ignore_public_acls and restrict_public_buckets left out: they default to false.
}

resource "aws_s3_account_public_access_block" "account" {
  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = true
}
