# Expected findings:
#  - SEC-AWS-VPC-FLOWLOGS-001 HIGH — aws_flow_log absent when aws_vpc present

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "main"
  }
}

# No aws_flow_log resource — VPC has no flow logging.
