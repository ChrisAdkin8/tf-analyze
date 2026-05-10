# Expected findings:
#  - SEC-AWS-LOG-RETENTION-001 HIGH — audit_logs bucket missing object_lock_configuration

resource "aws_s3_bucket" "audit_logs" {
  bucket = "org-audit-logs"
}
