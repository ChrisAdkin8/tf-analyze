# OWASP A07:2021 — Identification and Authentication Failures
# Cloud: AWS
#
# Three AWS auth-failure shapes:
#
#   1. IAM access keys (long-lived) issued to humans or services
#      where IAM roles + STS would suffice. Keys leak in logs,
#      backups, and developer workstations; STS tokens expire in
#      hours.
#   2. IAM password policy without MFA enforcement, length minimums,
#      or reuse history. An organisation-wide password policy is
#      free; not setting one is policy decay.
#   3. Lambda / EC2 / ECS configured without an IAM role — the
#      compute uses the default service principal or an over-broad
#      role.
#
# Real-world impact:
#   - 2018 Imperva, 2019 Capital One: both involved long-lived AWS
#     keys exposed via misconfiguration. STS tokens with 15-minute
#     TTL would have shrunk the blast radius to near zero.
#
# Expected tf-analyze findings:
#   - SEC-AWS-IAM-001  HIGH  IAM policy with wildcard resource
#                            (the pattern below also triggers it
#                            because the inline policy is `*`/`*`)
#
# Fix summary: replace human IAM users with SSO + role assumption;
# replace service IAM users with IAM roles + STS AssumeRole; declare
# `aws_iam_account_password_policy` with `require_*` flags + 14-char
# minimum + 24-version history.

# Long-lived IAM user — should be SSO + role.
resource "aws_iam_user" "human" {
  name = "demo-human"
}

resource "aws_iam_access_key" "human" {
  user = aws_iam_user.human.name
}

# Inline policy with wildcards — see also 01_broken_access_control.
resource "aws_iam_user_policy" "human_admin" {
  name = "demo-human-admin"
  user = aws_iam_user.human.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# Password policy that doesn't require MFA, complexity, or history.
resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length      = 6
  require_lowercase_characters = false
  require_uppercase_characters = false
  require_numbers              = false
  require_symbols              = false
  password_reuse_prevention    = 1
}
