# Expected findings:
#  - SEC-AWS-SSM-001 LOW — SSM parameter type is String, not SecureString
# (a parameter named like a secret is SEC-SECRETS-002, HIGH)

resource "aws_ssm_parameter" "feature_flags" {
  name  = "/app/config/feature-flags"
  type  = "String"
  value = "checkout_v2=on"
}
