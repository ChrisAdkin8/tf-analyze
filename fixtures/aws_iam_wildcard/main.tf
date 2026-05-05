# Expected findings:
#  - SEC-AWS-IAM-001 HIGH — IAM policy with Resource = "*"

data "aws_iam_policy_document" "too_broad" {
  statement {
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "too_broad" {
  name   = "too-broad"
  policy = data.aws_iam_policy_document.too_broad.json
}
