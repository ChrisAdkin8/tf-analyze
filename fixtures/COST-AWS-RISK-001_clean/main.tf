# Auto-generated clean fixture for COST-AWS-RISK-001.
# AWS resource missing cost control
# This is a CORRECT configuration; COST-AWS-RISK-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_cloudwatch_log_group" "app" {
  name              = "/app/logs"
  retention_in_days = 90
}

resource "aws_autoscaling_group" "app" {
  min_size         = 1
  max_size         = 10
  desired_capacity = 2
}
