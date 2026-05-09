# Clean fixture for ROB-FOREACH-002.
# Input-driven keyset: stable across upstream resource churn.

variable "private_subnet_cidrs" {
  type    = set(string)
  default = ["10.0.1.0/24", "10.0.2.0/24"]
}

resource "aws_subnet" "private" {
  for_each   = var.private_subnet_cidrs
  vpc_id     = "vpc-abc"
  cidr_block = each.key
}

# Keyed on the same input — stable, must NOT fire.
resource "aws_route_table_association" "rta" {
  for_each       = var.private_subnet_cidrs
  subnet_id      = aws_subnet.private[each.key].id
  route_table_id = "rtb-abc"
}

# Comprehension over a local — stable across upstream resource churn.
locals {
  team_names = toset(["alpha", "beta"])
}

resource "aws_iam_user" "team" {
  for_each = { for name in local.team_names : name => upper(name) }
  name     = each.key
}
