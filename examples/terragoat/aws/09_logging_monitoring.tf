# OWASP A09:2021 — Security Logging and Monitoring Failures
# Cloud: AWS
#
# Five AWS-specific shapes:
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
#
# Real-world impact:
#   - Without CloudTrail multi-region: an attacker who pivots into
#     a region you don't monitor is invisible. Most public AWS
#     incidents cite "no CloudTrail" or "CloudTrail in one region"
#     as a contributing factor.
#
# Expected tf-analyze findings:
#   - SEC-AWS-VPC-FLOWLOGS-001 (VPC without aws_flow_log)
#   - COST-AWS-RISK-001 (CloudWatch log group without retention_in_days)
#
# Fix summary: one CloudTrail trail with `is_multi_region_trail = true`
# and `enable_log_file_validation = true` per organisation; flow logs
# enabled on every VPC; CloudWatch log exports on every RDS instance.

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
  # No aws_s3_bucket_logging resource.
}

# CloudWatch log group without retention — billed per GB forever.
resource "aws_cloudwatch_log_group" "no_retention" {
  name = "/demo/app"
  # missing retention_in_days — logs never expire, cost drifts unbounded
}
