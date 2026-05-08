# Expected findings:
#  - ROB-AWS-SECRETSMANAGER-001 MEDIUM — no rotation configured

resource "aws_secretsmanager_secret" "api_key" {
  name       = "app/api/key"
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/abc-123"
}
# No aws_secretsmanager_secret_rotation resource
