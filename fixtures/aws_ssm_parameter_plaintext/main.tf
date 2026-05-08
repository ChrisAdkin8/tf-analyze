# Expected findings:
#  - SEC-AWS-SSM-001 HIGH — SSM parameter type is String, not SecureString

resource "aws_ssm_parameter" "db_password" {
  name  = "/app/db/password"
  type  = "String"
  value = "supersecret123"
}
