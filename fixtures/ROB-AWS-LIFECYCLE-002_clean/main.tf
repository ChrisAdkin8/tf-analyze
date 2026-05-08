# Auto-generated clean fixture for ROB-AWS-LIFECYCLE-002.
# S3 bucket has force_destroy enabled
# This is a CORRECT configuration; ROB-AWS-LIFECYCLE-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_s3_bucket" "example" {
  # ... other arguments ...
  force_destroy = false
}
