data "aws_iam_policy_document" "wildcard_action" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["arn:aws:s3:::my-bucket/*"]
  }
}
