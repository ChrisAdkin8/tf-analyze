# IAM role with a wildcard policy. This is the privilege-escalation
# rung on the attack graph: the web instance's profile resolves to this
# role, the role grants `s3:*` and `secretsmanager:*` on `*`, and the
# crown jewels (S3 bucket, Secrets Manager secret) match.

resource "aws_iam_role" "web" {
  name = "${var.app_name}-web-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Anti-pattern: wildcard Resource on every action group. Fires
# SEC-AWS-IAM-001 (and the engine's iam_json_policy_analysis pass).
resource "aws_iam_role_policy" "web_broad" {
  name = "${var.app_name}-web-broad"
  role = aws_iam_role.web.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*",
          "secretsmanager:*",
          "rds:*",
          "kms:Decrypt",
        ]
        Resource = "*"
      },
    ]
  })
}
