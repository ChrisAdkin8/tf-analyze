resource "aws_iam_role_policy" "iam_wild" {
  name = "iam-wild"
  role = "demo"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["iam:Create*", "iam:Attach*"],
        Resource = "*"
      }
    ]
  })
}
