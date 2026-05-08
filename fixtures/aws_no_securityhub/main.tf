# Expected findings:
#  - SEC-AWS-SECURITYHUB-001 MEDIUM — no aws_securityhub_account

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}
# No aws_securityhub_account resource
