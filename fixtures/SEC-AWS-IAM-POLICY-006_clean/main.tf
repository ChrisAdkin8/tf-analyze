# Clean fixture for SEC-AWS-IAM-POLICY-006.
# Negative form is only safe in a Deny statement, and an explicit Allow
# list is the fix; the rule must NOT fire on either, in either policy form.

data "aws_iam_policy_document" "deny_iam_changes" {
  statement {
    effect      = "Deny"
    not_actions = ["iam:*", "sts:*"]
    resources   = ["*"]
  }
}

resource "aws_iam_policy" "deny_outside_bucket" {
  name = "deny-outside-bucket"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = ["arn:aws:s3:::my-bucket/*"]
      },
      {
        Effect      = "Deny"
        Action      = "s3:*"
        NotResource = ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
      },
    ]
  })
}
