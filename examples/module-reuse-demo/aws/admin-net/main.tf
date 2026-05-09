# Tiny single-AZ admin network — VPC + 2 subnets, no IGW, no NAT.
#
# Resources present: aws_vpc + 2x aws_subnet. The fingerprint requires
# 3+ supporting types from {aws_internet_gateway, aws_nat_gateway,
# aws_eip, aws_route_table, aws_route_table_association, ...} — this
# directory has zero. Module Reuse Advisor MUST NOT fire.
#
# Negative case: demonstrates that the rule is conservative by design.
# Bespoke private networks (admin VPCs, isolated PCI workloads) are
# deliberately small and shouldn't be told to "use the community
# module".

resource "aws_vpc" "admin" {
  cidr_block = "10.99.0.0/24"

  tags = { Name = "admin-net", Purpose = "admin-only" }
}

resource "aws_subnet" "admin_a" {
  vpc_id            = aws_vpc.admin.id
  cidr_block        = "10.99.0.0/28"
  availability_zone = "us-east-1a"
}

resource "aws_subnet" "admin_b" {
  vpc_id            = aws_vpc.admin.id
  cidr_block        = "10.99.0.16/28"
  availability_zone = "us-east-1a"
}
