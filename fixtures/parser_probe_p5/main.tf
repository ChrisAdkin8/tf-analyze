# Parser-migration probe P5 — see tasks/hcl-parser-migration.md §1 and Appendix A.
resource "aws_cloudwatch_log_group" "l" {
  name = "l"
  tags = {
    retention_in_days = "none"
  }
}
