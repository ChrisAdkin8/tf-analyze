# Expected findings:
#   SEC-AWS-APIGW-001  MEDIUM  aws_api_gateway_stage missing access_log_settings

resource "aws_api_gateway_rest_api" "main" {
  name = "demo-api"
}

resource "aws_api_gateway_deployment" "main" {
  rest_api_id = aws_api_gateway_rest_api.main.id
}

resource "aws_api_gateway_stage" "no_logs" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.main.id
  deployment_id = aws_api_gateway_deployment.main.id
  # access_log_settings intentionally omitted
}
