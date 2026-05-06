# Expected findings:
#   STK-AWS-ECS-001  MEDIUM  aws_ecs_cluster missing setting block (Container Insights disabled)

resource "aws_ecs_cluster" "no_insights" {
  name = "demo-no-insights"
  # setting block intentionally omitted — Container Insights not configured
}
