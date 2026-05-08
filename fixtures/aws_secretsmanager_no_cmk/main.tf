# Expected findings:
#  - SEC-AWS-SECRETSMANAGER-001 MEDIUM — no kms_key_id

resource "aws_secretsmanager_secret" "db" {
  name        = "app/db/password"
  description = "Database password"
  # kms_key_id intentionally absent — uses aws/secretsmanager managed key
}
