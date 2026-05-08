data "aws_iam_policy_document" "wildcard_iam" {
  statement {
    effect    = "Allow"
    actions   = ["iam:Create*", "iam:Attach*"]
    resources = ["*"]
  }
}
