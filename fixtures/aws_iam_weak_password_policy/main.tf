# Expected findings:
#  - SEC-AWS-IAM-003 MEDIUM — password minimum_password_length below 14

resource "aws_iam_user" "admin" {
  name = "admin"
}

resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length        = 8
  require_lowercase_characters   = true
  require_numbers                = false
  require_uppercase_characters   = false
  require_symbols                = false
  allow_users_to_change_password = true
}
