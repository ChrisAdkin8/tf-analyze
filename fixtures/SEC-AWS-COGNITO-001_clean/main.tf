# Auto-generated clean fixture for SEC-AWS-COGNITO-001.
# Cognito user pool MFA not enabled
# This is a CORRECT configuration; SEC-AWS-COGNITO-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_cognito_user_pool" "example" {
  # ... other arguments ...
  mfa_configuration = "ON"
  software_token_mfa_configuration {
    enabled = true
  }
}
