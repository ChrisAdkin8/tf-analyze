# Auto-generated clean fixture for OPS-AWS-CWL-001.
# CloudWatch log group has no retention policy
# This is a CORRECT configuration; OPS-AWS-CWL-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_cloudwatch_log_group" "example" {
  name              = "example"
  retention_in_days = 90
}
