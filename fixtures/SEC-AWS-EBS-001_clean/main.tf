# Auto-generated clean fixture for SEC-AWS-EBS-001.
# EBS volume not encrypted
# This is a CORRECT configuration; SEC-AWS-EBS-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_ebs_volume" "example" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs.arn
}
