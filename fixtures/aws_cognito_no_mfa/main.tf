# Expected findings:
#   SEC-AWS-COGNITO-001  HIGH  mfa_configuration missing (defaults to OFF)

resource "aws_cognito_user_pool" "no_mfa" {
  name = "demo-no-mfa"
  # mfa_configuration intentionally omitted — defaults to OFF
}
