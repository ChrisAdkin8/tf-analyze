# OWASP A09:2021 — Security Logging and Monitoring Failures
# Cloud: AWS
#
# Six AWS-specific shapes:
#
#   1. No CloudTrail in the account, or CloudTrail without
#      multi-region enabled. The log of every API call is the
#      foundation of every AWS incident-response playbook.
#   2. CloudTrail without log-file integrity validation
#      (`enable_log_file_validation = false`). An attacker who
#      reaches the log bucket can edit the trail without trace.
#   3. VPC without flow logs. Lateral movement and data
#      exfiltration are invisible at the network layer.
#   4. RDS / Aurora without `enabled_cloudwatch_logs_exports` —
#      slow queries, error logs, and audit logs stay on the DB
#      instance.
#   5. S3 bucket without `aws_s3_bucket_logging` — read/write
#      access to objects is unaudited.
#   6. Route53 public zone without DNSSEC key-signing key —
#      DNS responses cannot be cryptographically validated.
#
# Real-world impact:
#   - Without CloudTrail multi-region: an attacker who pivots into
#     a region you don't monitor is invisible. Most public AWS
#     incidents cite "no CloudTrail" or "CloudTrail in one region"
#     as a contributing factor.
#
# Expected tf-analyze findings:
#   - SEC-AWS-VPC-FLOWLOGS-001   HIGH    VPC without aws_flow_log
#   - SEC-AWS-CLOUDTRAIL-001     HIGH    CloudTrail not multi-region
#   - SEC-AWS-CLOUDTRAIL-002     HIGH    CloudTrail log file validation disabled
#   - COST-AWS-RISK-001          MEDIUM  CloudWatch log group without retention_in_days
#   - STK-AWS-ROUTE53-001        HIGH    Route53 zone without DNSSEC key-signing key
#   - SEC-AWS-S3-LOGGING-001     MEDIUM  S3 bucket missing server access logging
#   - STK-AWS-EKS-005            HIGH    EKS cluster missing audit/authenticator log types
#
# Fix summary: one CloudTrail trail with `is_multi_region_trail = true`
# and `enable_log_file_validation = true` per organisation; flow logs
# enabled on every VPC; aws_s3_bucket_logging on every bucket.

# CloudTrail with no multi-region, no validation.
resource "aws_cloudtrail" "single_region" {
  name                          = "demo-single-region"
  s3_bucket_name                = "demo-cloudtrail-bucket"
  is_multi_region_trail         = false
  enable_log_file_validation    = false
  include_global_service_events = false
}

# VPC without flow logs.
resource "aws_vpc" "unmonitored" {
  cidr_block = "10.42.0.0/16"
  tags = {
    Name = "demo-unmonitored"
  }
  # No aws_flow_log resource pointing at this VPC.
}

# S3 bucket without access logging.
resource "aws_s3_bucket" "unlogged" {
  bucket = "demo-unlogged"
  # No aws_s3_bucket_logging resource — SEC-AWS-S3-LOGGING-001 fires.
}

# EKS cluster with partial control-plane logging: "audit" and
# "authenticator" intentionally omitted — STK-AWS-EKS-005 fires.
resource "aws_eks_cluster" "partial_logging" {
  name     = "demo-partial-logging"
  role_arn = "arn:aws:iam::123456789012:role/eks-role"

  vpc_config {
    subnet_ids = ["subnet-ccc", "subnet-ddd"]
  }

  enabled_cluster_log_types = ["api", "controllerManager", "scheduler"]
  # Missing: "audit", "authenticator"
}

# CloudWatch log group without retention — billed per GB forever.
resource "aws_cloudwatch_log_group" "no_retention" {
  name = "/demo/app"
  # missing retention_in_days — logs never expire, cost drifts unbounded
}

# Route53 public zone without DNSSEC. Without a key-signing key and
# the zone-signing infrastructure, resolvers cannot validate responses
# and DNS poisoning is undetectable.
resource "aws_route53_zone" "no_dnssec" {
  name = "demo.example.com"
  # No aws_route53_key_signing_key companion resource.
}
