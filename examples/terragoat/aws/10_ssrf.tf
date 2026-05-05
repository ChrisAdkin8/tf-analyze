# OWASP A10:2021 — Server-Side Request Forgery
# Cloud: AWS
#
# AWS gave the world the most famous SSRF incident — Capital One
# 2019. The attack chain:
#
#   1. WAF host had an SSRF vulnerability in a URL-fetching feature.
#   2. The attacker pointed it at `http://169.254.169.254/latest/
#      meta-data/iam/security-credentials/<role>` — the EC2 metadata
#      service.
#   3. IMDSv1 returned an STS token for the WAF's IAM role without
#      authentication.
#   4. The role had broad S3 read permissions.
#   5. 100M records exfiltrated.
#
# Three IaC-shaped controls prevent this:
#
#   1. EC2 instances configured with `metadata_options.http_tokens =
#      "required"` (IMDSv2 only — IMDSv1 disabled). IMDSv2 requires
#      a session token from a PUT call, which an SSRF can't easily
#      replay because most SSRF flaws only let an attacker *make*
#      requests, not *prepare* them.
#   2. Workloads bound to dedicated IAM roles with narrow grants —
#      even if metadata leaks, the role can't read every bucket.
#   3. VPC endpoints for S3 / DynamoDB / Secrets Manager — workloads
#      reach AWS services without leaving the VPC, eliminating
#      one class of SSRF target.
#
# Expected tf-analyze findings:
#   - (no AWS-specific catalogue rule for IMDSv2 yet; documented
#    as roadmap)
#
# Fix summary: every EC2 instance gets `metadata_options { http_tokens
# = "required" }`; every workload gets its own role; VPC endpoints
# for any AWS service the workload calls.

# EC2 with IMDSv1 enabled — the Capital One shape.
resource "aws_instance" "imds_v1" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  # metadata_options block intentionally omitted — IMDSv1 is the
  # default on older AMIs and on instances without explicit config.
}

# Same instance, but explicitly configured to allow IMDSv1 — same
# vulnerability, more visible.
resource "aws_instance" "imds_v1_explicit" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens   = "optional" # IMDSv1 still accepted
    http_endpoint = "enabled"
  }
}
