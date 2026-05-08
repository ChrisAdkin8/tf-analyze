# Auto-generated clean fixture for STK-AWS-ECS-001.
# ECS cluster Container Insights not configured
# This is a CORRECT configuration; STK-AWS-ECS-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_ecs_cluster" "example" {
  name = "example"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}
