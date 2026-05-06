resource "aws_s3_bucket" "ephemeral" {
  bucket        = "demo-force-destroy"
  force_destroy = true
  # Production bucket with force_destroy — a single terraform destroy
  # wipes all objects without confirmation.
}
