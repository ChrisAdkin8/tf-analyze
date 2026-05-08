# Auto-generated clean fixture for SEC-AWS-ALB-001.
# Load balancer access logs disabled
# This is a CORRECT configuration; SEC-AWS-ALB-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_lb" "example" {
  name               = "example"
  load_balancer_type = "application"
  access_logs {
    bucket  = aws_s3_bucket.logs.id
    prefix  = "alb"
    enabled = true
  }
}
