resource "aws_s3_bucket" "us" {
  provider = aws.us
  bucket   = "demo-us"
}

resource "aws_s3_bucket" "eu" {
  provider = aws.eu
  bucket   = "demo-eu"
}
