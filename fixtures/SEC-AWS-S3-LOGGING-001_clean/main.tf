resource "aws_s3_bucket" "app" {
  bucket = "my-app-bucket"
}

resource "aws_s3_bucket" "logs" {
  bucket = "my-app-access-logs"
}

resource "aws_s3_bucket_logging" "app" {
  bucket        = aws_s3_bucket.app.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "log/"
}
