# Expected findings:
#  - OPS-AWS-CWL-001 LOW — no retention_in_days

resource "aws_cloudwatch_log_group" "app" {
  name = "/app/prod"
  # No retention_in_days — defaults to never expire
}
