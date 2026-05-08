# Auto-generated clean fixture for SEC-AWS-APIGW-001.
# API Gateway stage missing access log destination
# This is a CORRECT configuration; SEC-AWS-APIGW-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_api_gateway_stage" "example" {
  # ... other arguments ...
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gw.arn
  }
}
