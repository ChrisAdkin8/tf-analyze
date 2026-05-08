# Expected findings: SEC-AWS-ECS-002
resource "aws_ecs_task_definition" "app" {
  family = "app"

  container_definitions = jsonencode([
    {
      name       = "app"
      image      = "app:latest"
      privileged = true
    }
  ])
}
