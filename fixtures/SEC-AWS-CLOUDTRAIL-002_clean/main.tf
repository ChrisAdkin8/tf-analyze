# Auto-generated clean fixture for SEC-AWS-CLOUDTRAIL-002.
# CloudTrail log file integrity validation disabled
# This is a CORRECT configuration; SEC-AWS-CLOUDTRAIL-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_cloudtrail" "example" {
  # ... other arguments ...
  enable_log_file_validation = true
}
