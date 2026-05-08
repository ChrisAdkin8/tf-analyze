# Auto-generated clean fixture for SEC-AWS-KMS-001.
# KMS key rotation disabled
# This is a CORRECT configuration; SEC-AWS-KMS-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_kms_key" "example" {
  description         = "..."
  enable_key_rotation = true
}
