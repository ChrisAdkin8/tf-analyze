# Expected findings:
#  - SEC-AWS-CLOUDTRAIL-001 HIGH — CloudTrail not enabled for all regions

resource "aws_s3_bucket" "trail_logs" {
  bucket        = "my-cloudtrail-logs"
  force_destroy = true
}

resource "aws_cloudtrail" "single_region" {
  name                  = "single-region-trail"
  s3_bucket_name        = aws_s3_bucket.trail_logs.id
  is_multi_region_trail = false
}
