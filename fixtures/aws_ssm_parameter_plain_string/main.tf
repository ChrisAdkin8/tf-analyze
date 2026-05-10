# Expected findings:
#  - SEC-SECRETS-002 HIGH — aws_ssm_parameter with type = "String" (not SecureString)

resource "aws_ssm_parameter" "db_password" {
  name  = "/prod/db/password"
  type  = "String"
  value = "hunter2"
}
