# The bucket the companion in main.tf configures. Kept in its own file:
# the companion must be found across files of the module (AWS provider
# v4+ split-resource style), not only in the same file.
resource "aws_s3_bucket" "example" {
  bucket = "example-bucket"
}
