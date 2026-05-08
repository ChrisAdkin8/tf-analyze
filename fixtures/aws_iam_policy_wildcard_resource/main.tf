data "aws_iam_policy_document" "wildcard_resource" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}
