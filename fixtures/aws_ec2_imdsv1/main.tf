# Expected findings:
#  - SEC-AWS-SSRF-001 HIGH — EC2 instance metadata service v1 enabled (IMDSv2 not enforced)

resource "aws_instance" "imdsv1" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  # No metadata_options block — IMDSv1 is allowed by default
  tags = {
    Name = "imdsv1-instance"
  }
}
