# Auto-generated clean fixture for OPS-AWS-TAGS-001.
# AWS resource missing tags
# This is a CORRECT configuration; OPS-AWS-TAGS-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_instance" "example" {
  # ... other arguments ...
  tags = {
    Environment = "prod"
    Owner       = "platform-team"
    Project     = "my-project"
  }
}
