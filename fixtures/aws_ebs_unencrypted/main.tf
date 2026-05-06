# Expected findings:
#  - SEC-AWS-EBS-001 HIGH — EBS volume not encrypted

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false

  tags = {
    Name = "unencrypted-volume"
  }
}
