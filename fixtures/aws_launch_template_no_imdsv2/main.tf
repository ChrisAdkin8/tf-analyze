# Expected findings: STK-AWS-LAUNCH-TEMPLATE-001

resource "aws_launch_template" "app" {
  name_prefix   = "demo-app-"
  image_id      = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  # No metadata_options block — IMDSv1 is accessible
}
