resource "aws_lb" "app" {
  name               = "app-lb"
  load_balancer_type = "application"
  subnets            = ["subnet-abc", "subnet-def"]
}

resource "aws_wafv2_web_acl" "example" {
  name  = "managed-rule-example"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "example"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "example" {
  resource_arn = aws_lb.app.arn
  web_acl_arn  = aws_wafv2_web_acl.example.arn
}

resource "aws_kinesis_firehose_delivery_stream" "waf" {
  name        = "aws-waf-logs-example"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose.arn
    bucket_arn = aws_s3_bucket.waf_logs.arn
  }
}

resource "aws_wafv2_logging_configuration" "example" {
  log_destination_configs = [aws_kinesis_firehose_delivery_stream.waf.arn]
  resource_arn            = aws_wafv2_web_acl.example.arn
}
