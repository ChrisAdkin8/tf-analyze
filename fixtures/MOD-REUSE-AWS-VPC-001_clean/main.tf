# Clean fixture for MOD-REUSE-AWS-VPC-001.
#
# A bare VPC + a single subnet — plausibly bespoke (e.g., a tiny
# admin-only network). The supporting-types threshold (3) is not
# met, so the fingerprint must NOT fire.

resource "aws_vpc" "admin" {
  cidr_block = "10.99.0.0/24"
}

resource "aws_subnet" "admin_only" {
  vpc_id     = aws_vpc.admin.id
  cidr_block = "10.99.0.0/28"
}

resource "aws_subnet" "admin_backup" {
  vpc_id     = aws_vpc.admin.id
  cidr_block = "10.99.0.16/28"
}
