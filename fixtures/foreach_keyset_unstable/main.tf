# Expected findings:
#  - ROB-FOREACH-002 HIGH — for_each over splat of another resource (RTA)
#  - ROB-FOREACH-002 HIGH — for_each over comprehension of another resource (policy)

resource "aws_subnet" "private" {
  for_each   = toset(["10.0.1.0/24", "10.0.2.0/24"])
  vpc_id     = "vpc-abc"
  cidr_block = each.key
}

# splat form — fires
resource "aws_route_table_association" "rta" {
  for_each       = toset(aws_subnet.private[*].id)
  subnet_id      = each.key
  route_table_id = "rtb-abc"
}

# comprehension form — fires
resource "aws_iam_role_policy_attachment" "att" {
  for_each   = toset([for s in aws_subnet.private : s.id])
  role       = "demo-role"
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}
