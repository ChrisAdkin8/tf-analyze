# Auto-generated clean fixture for STK-AWS-LAMBDA-002.
# Lambda function missing dead-letter queue configuration
# This is a CORRECT configuration; STK-AWS-LAMBDA-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_lambda_function" "example" {
  # ... other arguments ...
  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }
}
