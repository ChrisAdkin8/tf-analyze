# Expected findings:
#   SEC-AWS-CLOUDFRONT-001  HIGH    viewer_protocol_policy = "allow-all"
#   SEC-AWS-CLOUDFRONT-002  MEDIUM  no logging_config block

resource "aws_cloudfront_distribution" "insecure" {
  enabled = true

  origin {
    domain_name = "demo-bucket.s3.amazonaws.com"
    origin_id   = "s3origin"
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "s3origin"
    viewer_protocol_policy = "allow-all"

    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
  # logging_config intentionally omitted — SEC-AWS-CLOUDFRONT-002 fires
}
