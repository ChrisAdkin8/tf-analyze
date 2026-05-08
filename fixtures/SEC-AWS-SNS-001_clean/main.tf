# Auto-generated clean fixture for SEC-AWS-SNS-001.
# SNS topic missing KMS encryption
# This is a CORRECT configuration; SEC-AWS-SNS-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_sns_topic" "example" {
  name              = "example"
  kms_master_key_id = aws_kms_key.sns.arn
}
