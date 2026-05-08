data "aws_iam_policy_document" "not_action" {
  statement {
    effect      = "Allow"
    not_actions = ["iam:*"]
    resources   = ["*"]
  }
}
