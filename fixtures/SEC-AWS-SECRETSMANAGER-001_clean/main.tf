# Auto-generated clean fixture for SEC-AWS-SECRETSMANAGER-001.
# Secrets Manager secret uses AWS-managed key (no CMK)
# This is a CORRECT configuration; SEC-AWS-SECRETSMANAGER-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_secretsmanager_secret" "example" {
  name       = "example"
  kms_key_id = aws_kms_key.secrets.arn
}
