resource "aws_iam_role_policy" "public" {
  name = "public-trust"
  role = "demo"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Action    = "sts:AssumeRole",
        Resource  = "*",
        Principal = { AWS = "*" }
      }
    ]
  })
}
