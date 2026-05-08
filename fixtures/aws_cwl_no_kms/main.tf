# Expected findings:
#  - SEC-AWS-CWL-001 MEDIUM — no KMS CMK on log group

resource "aws_cloudwatch_log_group" "app" {
  name              = "/app/prod"
  retention_in_days = 90
  # No kms_key_id — encrypted with AWS-managed key
}
