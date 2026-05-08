# Auto-generated clean fixture for SEC-AWS-ATHENA-001.
# Athena workgroup results not encrypted
# This is a CORRECT configuration; SEC-AWS-ATHENA-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_athena_workgroup" "example" {
  name = "example"
  configuration {
    enforce_workgroup_configuration = true
    result_configuration {
      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.athena.arn
      }
    }
  }
}
