# Expected findings:
#  - SEC-AWS-ACCESSKEY-001 HIGH — Long-lived IAM access key created for a user

resource "aws_iam_user" "ci_user" {
  name = "ci-deploy-user"
}

resource "aws_iam_access_key" "ci_user" {
  user = aws_iam_user.ci_user.name
}
