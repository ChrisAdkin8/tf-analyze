# Expected findings:
#  - SEC-AWS-IAM-002 CRITICAL — IAM assume role policy with wildcard Principal

resource "aws_iam_role" "wildcard_principal" {
  name = "wildcard-principal-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "sts:AssumeRole"
      }
    ]
  })
}
