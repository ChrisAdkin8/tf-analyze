# Auto-generated clean fixture for SEC-AWS-ECR-001.
# ECR repository missing scan-on-push
# This is a CORRECT configuration; SEC-AWS-ECR-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_ecr_repository" "example" {
  name = "example"
  image_scanning_configuration {
    scan_on_push = true
  }
}
