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
#   - MOD-PIN-001  MEDIUM  Registry module source missing version
#
# Fix summary: pin Lambda runtimes to a non-deprecated version
# (consult the AWS Lambda runtimes page); use `data "aws_ami"` with
# `most_recent = true` and an owner filter rather than a hardcoded
# AMI ID; pin every module to an exact version.

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

# Module without version constraint.
module "unpinned_vpc" {
  source = "terraform-aws-modules/vpc/aws"
  # version intentionally omitted

  name = "demo-vpc"
  cidr = "10.0.0.0/16"
}
