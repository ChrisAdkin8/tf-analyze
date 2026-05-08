# Expected findings:
#  - ROB-AWS-BACKUP-001 MEDIUM — no aws_backup_plan

resource "aws_dynamodb_table" "app" {
  name         = "app"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  deletion_protection_enabled = true
  point_in_time_recovery { enabled = true }
}
resource "aws_iam_role" "app" {
  name               = "app"
  assume_role_policy = "{}"
}
# No aws_backup_plan defined
