# Expected findings:
#   STK-AWS-LAMBDA-003  LOW  no tracing_config block

resource "aws_sqs_queue" "dlq" {
  name = "demo-lambda-dlq"
}

resource "aws_lambda_function" "no_tracing" {
  function_name = "demo-no-tracing"
  role          = "arn:aws:iam::123456789012:role/lambda-role"
  handler       = "index.handler"
  runtime       = "python3.13"
  filename      = "function.zip"

  # dead_letter_config present — STK-AWS-LAMBDA-002 does NOT fire
  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  tags = { Name = "demo-no-tracing" }
  # tracing_config intentionally omitted — STK-AWS-LAMBDA-003 fires
}
