resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_securityhub_account" "example" {}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
  depends_on    = [aws_securityhub_account.example]
}
