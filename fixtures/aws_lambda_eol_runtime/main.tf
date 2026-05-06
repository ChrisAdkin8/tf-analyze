# Expected findings:
#  - STK-AWS-LAMBDA-001 HIGH — Lambda function uses end-of-life runtime

resource "aws_iam_role" "lambda_exec" {
  name = "lambda-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_lambda_function" "eol_runtime" {
  function_name = "eol-runtime-function"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "index.handler"
  runtime       = "nodejs14.x"
  filename      = "function.zip"
}
