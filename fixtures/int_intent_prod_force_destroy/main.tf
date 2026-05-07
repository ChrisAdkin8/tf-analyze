resource "aws_s3_bucket" "data" {
  bucket        = "prod-data-bucket"
  force_destroy = true

  tags = {
    Environment = "prod"
  }
}
