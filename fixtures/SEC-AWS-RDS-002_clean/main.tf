# Auto-generated clean fixture for SEC-AWS-RDS-002.
# RDS instance or Aurora cluster storage not encrypted
# This is a CORRECT configuration; SEC-AWS-RDS-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_db_instance" "example" {
  # ... other arguments ...
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
}
