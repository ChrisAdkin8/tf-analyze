resource "aws_cloudtrail" "no_validation" {
  name                       = "demo-trail"
  s3_bucket_name             = "demo-cloudtrail-bucket"
  is_multi_region_trail      = true
  # enable_log_file_validation intentionally absent — log files can be
  # tampered without detection.
}
