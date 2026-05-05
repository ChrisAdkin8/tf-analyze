terraform {
  backend "s3" {
    bucket = "different-state-bucket"
    key    = "env2/terraform.tfstate"
    region = "us-east-1"
  }
}

resource "aws_s3_bucket" "test" {
  bucket = "test"
}
