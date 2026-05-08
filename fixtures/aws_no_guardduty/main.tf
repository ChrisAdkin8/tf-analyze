# Expected findings:
#  - SEC-AWS-GUARDDUTY-001 HIGH — no aws_guardduty_detector

# This module manages IAM and VPC resources but never enables GuardDuty.
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_iam_role" "app" {
  name               = "app"
  assume_role_policy = "{}"
}
# No aws_guardduty_detector resource
