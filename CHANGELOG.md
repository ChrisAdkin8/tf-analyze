# Changelog

Rule counts and corpus finding counts are as of each round's commit.
Self-test fixture counts are cumulative.

---

## Round 12 — 2026-05-06

**Rules added (+12):**

AWS (8):
- `SEC-AWS-CLOUDFRONT-001` — CloudFront distribution with `viewer_protocol_policy = "allow-all"` (HTTP permitted); `resource_body_contains` on the raw block
- `SEC-AWS-CLOUDFRONT-002` — CloudFront distribution missing `logging_config` block; `resource_missing_arg`
- `SEC-AWS-COGNITO-001` — Cognito user pool MFA disabled or absent; `resource_missing_arg` + `resource_arg regex: 'OFF'`
- `SEC-AWS-SECRETSMANAGER-001` — Secrets Manager secret has no `aws_secretsmanager_secret_rotation` resource; `resource_absent` scope:repo
- `SEC-AWS-APIGW-001` — API Gateway stage missing `access_log_settings` block; `resource_missing_arg`
- `STK-AWS-LAMBDA-002` — Lambda function missing `dead_letter_config` (DLQ); `resource_missing_arg`
- `STK-AWS-LAMBDA-003` — Lambda function missing `tracing_config` (X-Ray); `resource_missing_arg`
- `STK-AWS-ECS-001` — ECS cluster missing `setting` block (container insights disabled); `resource_missing_arg`

GCP (3):
- `SEC-GCP-REDIS-001` — Cloud Memorystore Redis instance with `auth_enabled = false` or missing; `resource_missing_arg` + `resource_arg regex: 'false'`
- `SEC-GCP-REDIS-002` — Cloud Memorystore Redis instance with `transit_encryption_mode = "DISABLED"` or missing; `resource_missing_arg` + `resource_arg regex: 'DISABLED'`
- `STK-GCP-ARTIFACT-001` — Artifact Registry repository missing `kms_key_name` (CMEK); `resource_missing_arg`

Azure (1):
- `SEC-AZURE-VM-001` — Linux VM with `disable_password_authentication = false` or missing (CIS Azure 7.3); `resource_missing_arg` + `resource_arg regex: 'false'`

**Corpus changes:**
- `aws/05_security_misconfiguration.tf` — added `aws_cloudfront_distribution` (allow-all + no logging_config); fires CLOUDFRONT-001/002
- `aws/06_vulnerable_components.tf` — existing Lambda fires STK-AWS-LAMBDA-002/003 automatically (no explicit snippet needed but header comment updated)
- `aws/07_identification_auth.tf` — added `aws_cognito_user_pool` (no mfa_configuration); fires COGNITO-001
- `aws/02_cryptographic_failures.tf` — added `aws_secretsmanager_secret` (no rotation); fires SECRETSMANAGER-001 corpus-level
- `aws/09_logging_monitoring.tf` — added `aws_api_gateway_stage` + `aws_ecs_cluster`; fires APIGW-001/ECS-001
- `gcp/02_cryptographic_failures.tf` — added `google_redis_instance` (auth=false, TLS=DISABLED); fires REDIS-001/002
- `gcp/05_security_misconfiguration.tf` — added `google_artifact_registry_repository` (no kms_key_name); fires ARTIFACT-001
- `azure/07_identification_auth.tf` — added `azurerm_linux_virtual_machine` (disable_password_authentication=false); fires AZURE-VM-001
- `azure/03_injection.tf` — existing `azurerm_linux_virtual_machine.user_data_inject` (no disable_password_authentication) fires AZURE-VM-001 via `resource_missing_arg`

**Fixtures added (+11):** `aws_cloudfront_allow_all`, `aws_cognito_no_mfa`, `aws_secretsmanager_no_rotation`, `aws_apigw_no_access_logs`, `aws_lambda_no_dlq`, `aws_lambda_no_tracing`, `aws_ecs_no_container_insights`, `gcp_redis_no_auth`, `gcp_redis_no_tls`, `gcp_artifact_no_cmek`, `azure_linux_vm_password_auth`

**Documentation:**
- `SKILL.md` — added `resource_arg` match modes section documenting `regex` vs `not_regex` and `block_arg_value` quote-stripping behaviour

**Corpus:** 260 → 274 findings. **Rules:** 142 → 154. **Self-test:** 140 → 151/151.

---

## Round 11 — 2026-05-06

**Rules added (+4):**
- `SEC-GCP-SA-KEY-001` — GCP service account key created in Terraform (static SA keys end up in TF state); `resource_present: google_service_account_key`
- `SEC-GCP-NETWORK-004` — GCP firewall rule exposes database/cache port to 0.0.0.0/0 (`firewall_open_port` for MySQL/PostgreSQL/MSSQL/Redis/MongoDB/Elasticsearch/Memcached)
- `SEC-AWS-S3-LOGGING-001` — S3 bucket missing server access logging (`resource_absent: aws_s3_bucket_logging` when `aws_s3_bucket` present)
- `STK-AWS-EKS-005` — EKS cluster has `enabled_cluster_log_types` but is missing `audit` or `authenticator` log types (uses new `not_regex` field on `resource_arg`)

**Rules extended:**
- `ROB-AWS-RDS-001`, `ROB-AWS-RDS-002`, `ROB-AWS-RDS-003`, `SEC-AWS-RDS-001`, `SEC-AWS-RDS-002` — all 5 RDS rules extended with parallel patterns for `aws_rds_cluster` / `aws_rds_cluster_instance` (Aurora coverage)

**CIS mappings added:**
- 35 AWS/Azure rules updated with CIS mappings: CIS AWS Foundations Benchmark v3.0 (CloudTrail, S3, RDS, KMS, VPC flow logs, SG, EKS, EBS, GuardDuty, IAM) and CIS Azure Foundations Benchmark v2.0 (Key Vault, SQL, RBAC, NSG, Storage, Monitor)

**Engine changes:**
- `not_regex` field added to `resource_arg` pattern kind: fires when attribute is present but its value does NOT match the given regex. Enables partial-config detection (e.g., EKS log types present but missing "audit")
- `hcl_context: true` added to `SEC-SECRETS-001` `.tf` grep patterns: strips HCL comments before matching to prevent false positives on commented-out credential examples
- SARIF `helpUri` base URL corrected from `anthropics/claude-code` to `ChrisAdkin8/tf-analyze`
- SARIF `informationUri` corrected to point at correct repository

**Fixtures added (+4):** `gcp_sa_key`, `gcp_firewall_db_port`, `aws_s3_no_logging`, `aws_eks_partial_logging`

**Corpus:** 252 → 260 findings. **Rules:** 138 → 142. **Self-test:** 136 → 140/140.

---

## Round 10 — 2026-05-06

**Rules added (+8):**
- `SEC-AWS-GUARDDUTY-001` — AWS GuardDuty detector not enabled (resource_absent when aws_vpc present)
- `SEC-AWS-ECR-002` — ECR repository missing image lifecycle policy (resource_absent)
- `SEC-AZURE-MONITOR-001` — Azure subscription missing activity log diagnostic setting (resource_absent)
- `SEC-GCP-COMPUTE-SHIELDED-001` — GCP Compute instance missing shielded_instance_config
- `STK-AWS-LAUNCH-TEMPLATE-001` — EC2 launch template does not enforce IMDSv2 (http_tokens = required)
- `ROB-VERSION-003` — required_providers entry missing version constraint (new engine kind: providers_version_missing)

**Engine changes:**
- `--output PATH` flag: write report to a file instead of stdout (stderr unaffected)
- SARIF `partialFingerprints` now emits two keys: `tfAnalyze/v1` (full file+resource) and `tfAnalyze/v1-resource` (resource-only). GitHub Code Scanning uses the most-specific matching key, so renaming a `.tf` file no longer emits false RESOLVED+NEW pairs for every finding in it.
- New corpus-level pattern kind `providers_version_missing` added to detect.py

**Corpus:** 246 → 252 findings. **Rules:** ~141 → ~149. **Self-test:** 130 → 136/136.

---

## Round 9 — 2026-05-06

**Rules added (+17): AWS/Azure parity with GCP**

AWS (8):
- `ROB-AWS-RDS-003` — RDS instance missing deletion_protection
- `STK-AWS-RDS-004` — RDS EOL engine version (MySQL 5.6, Postgres 9.6–12)
- `ROB-AWS-LIFECYCLE-002` — S3 bucket has force_destroy = true
- `STK-AWS-EKS-001` — EKS endpoint_private_access not enabled
- `STK-AWS-EKS-002` — EKS control plane logging not enabled
- `STK-AWS-EKS-003` — EKS secrets encryption not configured
- `STK-AWS-EKS-004` — EKS OIDC provider absent (no IRSA)
- `STK-AWS-ROUTE53-001` — Route53 zone without DNSSEC key-signing key

Azure (9):
- `STK-AZURE-AKS-003` — AKS workload identity not enabled
- `STK-AZURE-AKS-004` — AKS not a private cluster
- `STK-AZURE-AKS-005` — AKS API server missing authorized IP ranges
- `STK-AZURE-STORAGE-001` — Storage account missing blob versioning
- `SEC-AZURE-SQL-002` — SQL Server firewall rule allows all IPs
- `STK-AZURE-SQL-001` — Deprecated MySQL/PostgreSQL single-server resource
- `SEC-AZURE-KV-003` — Key Vault key missing rotation policy
- `SEC-AZURE-ACR-001` — Container Registry admin account enabled
- `STK-AZURE-DB-001` — MySQL/PostgreSQL server missing SSL enforcement

**Also fixed:** `STK-AWS-LAMBDA-001.yaml` YAML parse error (double-quoted regex with `\.` escape sequences).

**Corpus:** 203 → 246 findings. **Rules:** ~124 → ~141. **Self-test:** 113 → 130/130.

---

## Round 8 — 2026-05-05

**Rules added (+6):**
- `SEC-AZURE-AKS-002` — AKS cluster missing network policy
- `SEC-AZURE-KV-002` — Key Vault missing network ACL deny-by-default
- `SEC-AZURE-WEBAPP-002` — App Service / Function App HTTPS not enforced
- `STK-AZURE-SQL-TDE-001` — Azure SQL Database missing TDE resource (resource_absent)
- `SEC-AWS-CLOUDTRAIL-002` — CloudTrail log file integrity validation disabled
- `STK-GCP-PUBSUB-001` — Pub/Sub topic missing customer-managed encryption key

**Engine changes:**
- Added `suppress_if` field to `resource_missing_arg` pattern kind (static and plan-time handlers). Allows a rule to be suppressed when an alternative attribute provides equivalent security (e.g., SQS `sqs_managed_sse_enabled = true` suppresses the `kms_master_key_id` absence finding).
- Fixed `SEC-AWS-SQS-001` false positive: now suppressed when `sqs_managed_sse_enabled = true`.

**Corpus:** ~192 → 203 findings. **Rules:** ~118 → ~124.

---

## Round 7 — 2026-05-04

**Rules added:** Azure UAMI orphan check (`SEC-AZURE-MI-001`), `graph_check` for UAMI orphan detection, CloudTrail multi-region (`SEC-AWS-CLOUDTRAIL-001`), IMDSv2 enforcement on EC2 (`SEC-AWS-SSRF-001`), and several SQS/SNS/ElastiCache encryption rules.

---

## Round 6 — 2026-05-03

**Rules added:** Azure coverage — RBAC subscription-scope (`SEC-AZURE-RBAC-001`), storage (`SEC-AZURE-STORAGE-001/002`, `ROB-AZURE-STORAGE-001`), Key Vault (`SEC-AZURE-KV-001`, `SEC-AZURE-LOGGING-001`), AKS RBAC (`SEC-AZURE-AKS-001`), SQL AAD admin (`SEC-AZURE-SQL-001`), SQL backup (`ROB-AZURE-SQL-001`), NSG flow logs (`STK-AZURE-NSG-FLOWLOG-001`), NSG open ports (`STK-AZURE-NSG-001`), lifecycle prevent_destroy (`ROB-AZURE-LIFECYCLE-001`), tags (`OPS-AZURE-TAGS-001`), HTTPS-only App Service (`SEC-AZURE-WEBAPP-001`).

---

## Round 1–5 — initial development

Initial skill build: GCP-first catalog (~90 rules), AWS secondary (~15 rules at start), terragoat demo corpus, self-test framework, SARIF/HTML/JSON output, delta tracking, suppression with expiry, `--new-rule` scaffolding, `python-hcl2` fast-path, CI integrations (pre-commit + GitHub Actions).
