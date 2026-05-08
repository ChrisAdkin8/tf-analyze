# Expected findings:
#  - SEC-AWS-ATHENA-001 MEDIUM — Athena workgroup results not encrypted

resource "aws_athena_workgroup" "main" {
  name = "main"

  configuration {
    enforce_workgroup_configuration = true
    result_configuration {
      output_location = "s3://my-results-bucket/output/"
      # No encryption_configuration block
    }
  }
}
