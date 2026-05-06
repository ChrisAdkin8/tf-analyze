# Expected findings:
#  - SEC-AWS-KMS-001 HIGH — KMS key rotation disabled

resource "aws_kms_key" "no_rotation" {
  description             = "KMS key with rotation disabled"
  deletion_window_in_days = 10
  enable_key_rotation     = false
}
