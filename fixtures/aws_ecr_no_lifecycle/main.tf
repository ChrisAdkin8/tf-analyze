# Expected findings: SEC-AWS-ECR-002
# (aws_ecr_repository present but no aws_ecr_lifecycle_policy — fires via resource_absent)

resource "aws_ecr_repository" "app" {
  name                 = "demo-app"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
  # No aws_ecr_lifecycle_policy companion resource
}
