# Expected findings:
#  - SEC-AWS-BACKUP-001 MEDIUM — no kms_key_arn on backup vault

resource "aws_backup_vault" "main" {
  name = "main"
  # kms_key_arn intentionally absent — uses aws/backup managed key
}
