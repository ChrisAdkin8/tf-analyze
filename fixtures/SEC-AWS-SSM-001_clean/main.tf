# Auto-generated clean fixture for SEC-AWS-SSM-001.
# SSM Parameter Store parameter not encrypted as SecureString
# This is a CORRECT configuration; SEC-AWS-SSM-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_ssm_parameter" "example" {
  name   = "/app/secret"
  type   = "SecureString"
  value  = var.secret_value
  key_id = aws_kms_key.ssm.arn
}
