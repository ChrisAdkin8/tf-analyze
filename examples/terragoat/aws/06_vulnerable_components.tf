# OWASP A06:2021 — Vulnerable and Outdated Components
# Cloud: AWS
#
# Three AWS-specific shapes:
#
#   1. Lambda runtime pinned to an EOL version (`nodejs10.x`,
#      `python3.6`, `dotnetcore2.1`). AWS deprecates these on a
#      schedule; once deprecated, no security patches and the
#      function eventually fails to invoke.
#   2. EC2 AMI ID hardcoded in HCL — a year later the AMI is
#      missing CVE patches that landed in newer builds.
#   3. Module sources without `version` constraint — same shape as
#      GCP A06.
#
# Real-world impact:
#   - Functions on EOL runtimes are a CVE-exposure shape in AWS:
#     once Lambda stops shipping security patches, the function is
#     running unmaintained code in production.
#
# Expected tf-analyze findings:
#   - MOD-PIN-001                 MEDIUM  Registry module source missing version
#   - STK-AWS-EKS-001             HIGH    EKS endpoint_private_access not enabled
#   - STK-AWS-EKS-002             HIGH    EKS control plane logging not enabled
#   - STK-AWS-EKS-003             HIGH    EKS secrets encryption not configured
#   - STK-AWS-EKS-004             HIGH    EKS OIDC provider absent (no IRSA)
#   - STK-AWS-LAUNCH-TEMPLATE-001 HIGH    Launch template does not enforce IMDSv2
#   - STK-AWS-LAMBDA-001          HIGH    Lambda function on EOL runtime (nodejs10.x)
#   - STK-AWS-LAMBDA-002          MEDIUM  Lambda function missing dead-letter queue
#   - STK-AWS-LAMBDA-003          LOW     Lambda function missing X-Ray tracing
#
# Fix summary: pin Lambda runtimes to a non-deprecated version
# (consult the AWS Lambda runtimes page); use `data "aws_ami"` with
# `most_recent = true` and an owner filter rather than a hardcoded
# AMI ID; pin every module to an exact version. Enable private endpoint,
# logging, secrets encryption, and IRSA on every EKS cluster.

# Lambda on an EOL runtime.
resource "aws_lambda_function" "eol_runtime" {
  filename      = "function.zip"
  function_name = "demo-eol-runtime"
  role          = "arn:aws:iam::123456789012:role/lambda-role"
  handler       = "index.handler"
  runtime       = "nodejs10.x" # EOL since early 2022

  environment {
    variables = {
      ENV = "demo"
    }
  }
}

# Hardcoded AMI ID — frozen in time.
resource "aws_instance" "frozen_ami" {
  ami           = "ami-0c55b159cbfafe1f0" # Ubuntu 18.04 from 2018
  instance_type = "t3.micro"
}

# Launch template without IMDSv2 enforcement. Used by EKS node groups
# and standalone EC2 — any pod or workload with SSRF can reach
# 169.254.169.254 and steal the node's IAM role credentials.
resource "aws_launch_template" "insecure" {
  name_prefix   = "demo-insecure-"
  image_id      = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  # No metadata_options block — IMDSv1 accessible
}

# EKS cluster with no private endpoint, no logging, no secrets encryption.
# Missing OIDC provider means workloads cannot use IAM Roles for
# Service Accounts (IRSA) — they fall back to the node's instance role.
resource "aws_eks_cluster" "insecure" {
  name     = "demo-insecure"
  role_arn = "arn:aws:iam::123456789012:role/eks-role"

  vpc_config {
    subnet_ids = ["subnet-aaa", "subnet-bbb"]
    # endpoint_private_access not set — public API endpoint only
  }
  # enabled_cluster_log_types not set — no audit/API server logging
  # encryption_config not set — secrets unencrypted in etcd
}
# No aws_iam_openid_connect_provider — IRSA impossible

# Module without version constraint.
module "unpinned_vpc" {
  source = "terraform-aws-modules/vpc/aws"
  # version intentionally omitted

  name = "demo-vpc"
  cidr = "10.0.0.0/16"
}
