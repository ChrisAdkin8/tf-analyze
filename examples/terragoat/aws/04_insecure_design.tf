# OWASP A04:2021 — Insecure Design
# Cloud: AWS
#
# Two design-level failures common in AWS Terraform:
#
#   1. Hardcoded credentials in HCL — passwords, API keys, access
#      tokens checked into git. Even after the file is removed, the
#      credential lives forever in history (and the secret is
#      already compromised at the moment of the first push).
#   2. Single shared IAM role assumed by every Lambda / ECS task /
#      EC2 instance. A compromise of any compute resource inherits
#      the union of every grant the team ever needed.
#   3. No `lifecycle { prevent_destroy = true }` on stateful
#      resources (RDS, DynamoDB tables, S3 state buckets, KMS
#      CMKs). A typo'd `terraform destroy` against the wrong
#      workspace wipes the data plane.
#
# Real-world impact:
#   - 2016 Uber: 57M records leaked via AWS access keys committed to
#     a private GitHub repo.
#   - 2018 Tesla: cryptojackers exploited a shared Kubernetes /
#     AWS role to mine in the production cluster.
#
# Expected tf-analyze findings:
#   - (Step 0a credential pattern detection — see SKILL.md — flags
#     hardcoded AKIA / sk- / ghp_ patterns in tfvars at scan time)
#   - ROB-AWS-LIFECYCLE-001 (DynamoDB/RDS/S3/ElastiCache missing lifecycle.prevent_destroy)
#
# Fix summary: secrets via AWS Secrets Manager / SSM Parameter Store
# fetched at runtime, never hardcoded; one IAM role per workload
# boundary; `lifecycle { prevent_destroy = true }` on every
# non-replaceable resource.

# Hardcoded credential in HCL — the moment this hits any git history,
# the secret is compromised.
locals {
  api_key = "sk-live-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}

# Shared role assumed by every Lambda function in the stack.
resource "aws_iam_role" "all_lambdas" {
  name = "demo-all-lambdas"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "all_lambdas_admin" {
  role       = aws_iam_role.all_lambdas.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# DynamoDB table without prevent_destroy.
resource "aws_dynamodb_table" "stateful" {
  name           = "demo-stateful"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }
  # No lifecycle { prevent_destroy = true }
}
