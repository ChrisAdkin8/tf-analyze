# Expected findings:
#   STK-AWS-LAMBDA-002  MEDIUM  no dead_letter_config block

resource "aws_lambda_function" "no_dlq" {
  function_name = "demo-no-dlq"
  role          = "arn:aws:iam::123456789012:role/lambda-role"
  handler       = "index.handler"
  runtime       = "python3.13"
  filename      = "function.zip"

  # tracing_config present — STK-AWS-LAMBDA-003 does NOT fire
  tracing_config {
    mode = "Active"
  }

  tags = { Name = "demo-no-dlq" }
  # dead_letter_config intentionally omitted — STK-AWS-LAMBDA-002 fires
}
