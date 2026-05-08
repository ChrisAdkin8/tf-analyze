# Auto-generated clean fixture for SEC-AWS-CLOUDFRONT-001.
# CloudFront distribution serves HTTP without redirect
# This is a CORRECT configuration; SEC-AWS-CLOUDFRONT-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_cloudfront_distribution" "example" {
  default_cache_behavior {
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "example"
    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }
  }
}
