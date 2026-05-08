# Auto-generated clean fixture for SEC-AWS-BACKUP-001.
# Backup vault uses AWS-managed key (no CMK)
# This is a CORRECT configuration; SEC-AWS-BACKUP-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_backup_vault" "example" {
  name        = "example"
  kms_key_arn = aws_kms_key.backup.arn
}
