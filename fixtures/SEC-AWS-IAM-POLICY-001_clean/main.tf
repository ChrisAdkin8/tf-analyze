# Clean fixture for SEC-AWS-IAM-POLICY-001.
# Wildcard `actions = ["*"]` is NOT used; SEC-AWS-IAM-POLICY-001 must NOT fire.

data "aws_iam_policy_document" "least_privilege" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["arn:aws:s3:::my-bucket/*"]
  }
}
