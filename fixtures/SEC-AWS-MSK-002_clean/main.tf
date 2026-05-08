# Auto-generated clean fixture for SEC-AWS-MSK-002.
# MSK cluster does not use CMK for encryption at rest
# This is a CORRECT configuration; SEC-AWS-MSK-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_msk_cluster" "example" {
  cluster_name = "example"
  encryption_info {
    encryption_at_rest {
      encryption_at_rest_kms_key_arn = aws_kms_key.msk.arn
    }
  }
}
