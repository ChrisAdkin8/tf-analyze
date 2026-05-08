# Auto-generated clean fixture for STK-AWS-LAMBDA-001.
# Lambda function uses end-of-life runtime
# This is a CORRECT configuration; STK-AWS-LAMBDA-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_lambda_function" "example" {
  function_name = "example"
  role          = aws_iam_role.lambda.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  filename      = "function.zip"
}
