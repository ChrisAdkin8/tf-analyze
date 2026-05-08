# Auto-generated clean fixture for SEC-AWS-SQS-001.
# SQS queue missing server-side encryption
# This is a CORRECT configuration; SEC-AWS-SQS-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_sqs_queue" "example" {
  name              = "example"
  kms_master_key_id = aws_kms_key.sqs.arn
}
