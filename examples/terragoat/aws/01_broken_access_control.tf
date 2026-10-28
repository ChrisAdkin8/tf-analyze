# OWASP A01:2021 — Broken Access Control
# Cloud: AWS
#
# Three AWS-shaped patterns:
#
#   1. IAM policy with `Action: "*"` and `Resource: "*"` — the AWS
#      equivalent of GCP's `roles/owner`. An attacker holding this
#      can read every secret in Secrets Manager, every object in
#      every bucket, and replay every API call.
#   2. S3 bucket with `acl = "public-read"` (or via
#      `aws_s3_bucket_public_access_block.block_public_acls = false`).
#      Anonymous reads on every object.
#   3. IAM role assumed by every service principal (`Principal: "*"`)
#      — anyone in any AWS account can assume it.
#
# Real-world impact:
#   - 2019 Capital One: SSRF + over-broad IAM = 100M records leaked.
#   - 2017 Verizon, 2017 Accenture, 2018 FedEx, 2019 Booz Allen:
#     all public-S3 incidents.
#
# Expected tf-analyze findings:
#   - SEC-AWS-IAM-POLICY-005  CRITICAL  IAM policy document with actions and resources `*`
#   - SEC-AWS-S3-001   HIGH   S3 bucket missing server-side encryption
#   - SEC-AWS-S3-PUBLIC-BLOCK-001  HIGH  S3 bucket with no public access block
#   - SEC-AWS-S3-PUBLIC-001        HIGH  S3 bucket ACL `public-read`
#
# Fix summary: scope every IAM policy to specific Actions and
# Resources; declare `aws_s3_bucket_public_access_block` with all
# four flags set to `true` on every bucket; restrict `assume_role_policy`
# to specific service principals or account IDs.

# IAM policy with wildcard everything — the canonical anti-pattern.
data "aws_iam_policy_document" "all_access" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
       resources = ["*"]
  }
}

resource "aws_iam_policy" "godmode" {
  name   = "demo-godmode"
  policy = data.aws_iam_policy_document.all_access.json
}

# S3 bucket with no public-access block — anonymous reads are
# possible if any future binding grants public.
resource "aws_s3_bucket" "no_block" {
  bucket = "demo-no-public-access-block"
}

# ... and a canned ACL that hands every object to anyone on the internet.
resource "aws_s3_bucket_acl" "no_block" {
  bucket = aws_s3_bucket.no_block.id
  acl    = "public-read"
}

# IAM role with wildcard principal — every AWS account can assume it.
resource "aws_iam_role" "anyone" {
  name = "demo-anyone-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "sts:AssumeRole"
    }]
  })
}
