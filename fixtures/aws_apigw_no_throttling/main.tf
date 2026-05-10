# Expected findings:
#  - SEC-AWS-APIGW-002 MEDIUM — method_settings missing settings { throttling_* }

resource "aws_api_gateway_method_settings" "all" {
  rest_api_id = "abc"
  stage_name  = "prod"
  method_path = "*/*"
}
