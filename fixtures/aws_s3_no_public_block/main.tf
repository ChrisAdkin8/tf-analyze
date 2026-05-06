# Expected findings:
#  - SEC-AWS-S3-PUBLIC-BLOCK-001 HIGH — aws_s3_bucket present but no aws_s3_bucket_public_access_block

resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"

  # No aws_s3_bucket_public_access_block resource — bucket may be made public.
}
