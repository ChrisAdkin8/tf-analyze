# Auto-generated clean fixture for SEC-AWS-CWL-001.
# CloudWatch log group not encrypted with KMS CMK
# This is a CORRECT configuration; SEC-AWS-CWL-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_cloudwatch_log_group" "example" {
  name              = "example"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.logs.arn
}
