resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_cloudwatch_log_group" "vpc_flow" {
  name              = "/aws/vpc/flowlogs"
  retention_in_days = 90
}

resource "aws_flow_log" "main" {
  iam_role_arn    = aws_iam_role.vpc_flow.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id
}
