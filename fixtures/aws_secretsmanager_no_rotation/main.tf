# Expected findings:
#   SEC-AWS-SECRETSMANAGER-001  MEDIUM  no aws_secretsmanager_secret_rotation (resource_absent)

resource "aws_secretsmanager_secret" "app" {
  name        = "demo-app-secret"
  description = "Application secret without rotation configured"
  # No aws_secretsmanager_secret_rotation companion resource.
}
