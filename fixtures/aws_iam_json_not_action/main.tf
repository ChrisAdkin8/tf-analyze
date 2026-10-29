# Expected findings:
# - SEC-AWS-IAM-POLICY-006 MEDIUM aws_iam_policy.not_action (jsonencode NotAction + NotResource)
# - SEC-AWS-IAM-POLICY-006 MEDIUM aws_iam_user_policy.not_resource (heredoc NotResource)
#
# Negative-form Allow grants written as JSON. The rule used to read
# `aws_iam_policy_document` only, so neither of these was reported.

# Everything except IAM, on everything except one bucket.
resource "aws_iam_policy" "not_action" {
  name = "power-user-ish"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect      = "Allow"
      NotAction   = ["iam:*"]
      NotResource = ["arn:aws:s3:::audit-bucket"]
    }]
  })
}

resource "aws_iam_user_policy" "not_resource" {
  name   = "s3-read-elsewhere"
  user   = "ci"
  policy = <<-EOF
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": "s3:GetObject",
          "NotResource": "arn:aws:s3:::payroll/*"
        }
      ]
    }
  EOF
}
