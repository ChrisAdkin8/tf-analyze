# Expected findings:
#  - OPS-AWS-TAGS-001 MEDIUM — aws_instance missing tags
#  - OPS-AWS-TAGS-001 MEDIUM — aws_s3_bucket missing tags
#  - OPS-AWS-TAGS-001 MEDIUM — aws_vpc missing tags

resource "aws_instance" "app" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  # No tags block.
}

resource "aws_s3_bucket" "data" {
  bucket = "my-untagged-bucket"
  # No tags block.
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  # No tags block.
}
