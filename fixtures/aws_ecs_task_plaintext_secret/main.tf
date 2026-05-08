# Expected findings: SEC-AWS-ECS-001
resource "aws_ecs_task_definition" "app" {
  family = "app"

  container_definitions = jsonencode([
    {
      name  = "app"
      image = "app:latest"

      environment = [
        {
          name  = "DATABASE_PASSWORD"
          value = "supersecret123"
        },
        {
          name  = "PORT"
          value = "8080"
        }
      ]
    }
  ])
}
