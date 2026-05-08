# Auto-generated clean fixture for SEC-AWS-CLOUDFRONT-002.
# CloudFront distribution missing access logging
# This is a CORRECT configuration; SEC-AWS-CLOUDFRONT-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_cloudfront_distribution" "example" {
  # ... other arguments ...
  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.logs.bucket_domain_name
    prefix          = "cloudfront/"
  }
}
