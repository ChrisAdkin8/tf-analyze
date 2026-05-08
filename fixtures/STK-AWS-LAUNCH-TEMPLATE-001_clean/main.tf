# Auto-generated clean fixture for STK-AWS-LAUNCH-TEMPLATE-001.
# EC2 launch template does not enforce IMDSv2
# This is a CORRECT configuration; STK-AWS-LAUNCH-TEMPLATE-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_launch_template" "example" {
  name = "example"
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }
}
