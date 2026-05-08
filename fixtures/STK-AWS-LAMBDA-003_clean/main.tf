# Auto-generated clean fixture for STK-AWS-LAMBDA-003.
# Lambda function active X-Ray tracing not configured
# This is a CORRECT configuration; STK-AWS-LAMBDA-003 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_lambda_function" "example" {
  # ... other arguments ...
  tracing_config {
    mode = "Active"
  }
}
