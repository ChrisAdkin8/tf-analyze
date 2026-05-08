resource "aws_backup_plan" "example" {
  name = "tf-backup-plan"

  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.example.name
    schedule          = "cron(0 5 ? * * *)"

    lifecycle {
      delete_after = 14
    }
  }
}

resource "aws_backup_vault" "example" {
  name = "example-vault"
}

resource "aws_backup_selection" "example" {
  iam_role_arn = aws_iam_role.backup.arn
  name         = "tf-backup-selection"
  plan_id      = aws_backup_plan.example.id

  resources = ["*"]
}

resource "aws_iam_role" "backup" {
  name               = "backup-role"
  assume_role_policy = data.aws_iam_policy_document.backup_assume.json
}
