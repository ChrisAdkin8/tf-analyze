# Clean fixture for SEC-AWS-IAM-POLICY-005.
# No statement combines actions=["*"] AND resources=["*"]; rule must NOT fire.
# (Wildcard action-only or wildcard resource-only patterns are scoped to other rules.)

data "aws_iam_policy_document" "scoped" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::my-bucket/*"]
  }
}
