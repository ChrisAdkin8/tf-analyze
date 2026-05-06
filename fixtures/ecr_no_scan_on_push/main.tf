# Expected findings:
#  - SEC-AWS-ECR-001 HIGH — aws_ecr_repository missing image_scanning_configuration.scan_on_push

resource "aws_ecr_repository" "app" {
  name = "app"

  # No image_scanning_configuration block — scan-on-push disabled (default).
}
