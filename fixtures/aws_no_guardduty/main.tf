# Expected findings: SEC-AWS-GUARDDUTY-001
# (no aws_guardduty_detector resource — fires via resource_absent when aws_vpc present)

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  # No aws_guardduty_detector companion resource
}
