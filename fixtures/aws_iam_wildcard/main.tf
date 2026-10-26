# Expected findings:
#  - SEC-AWS-IAM-001 HIGH — inline IAM policy JSON with Resource = "*"
# (the aws_iam_policy_document form is SEC-AWS-IAM-POLICY-003)

resource "aws_iam_policy" "too_broad" {
  name = "too-broad"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "*"
    }]
  })
}
