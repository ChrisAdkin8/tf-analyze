# Auto-generated clean fixture for SEC-AWS-CLOUDTRAIL-001.
# CloudTrail not enabled for all regions
# This is a CORRECT configuration; SEC-AWS-CLOUDTRAIL-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_cloudtrail" "example" {
  # ... other arguments ...
  is_multi_region_trail = true
  include_global_service_events = true
}
