---
title: tf-analyze rule reference
---

# tf-analyze rule reference

Per-rule documentation auto-generated from the catalogue YAML ([`catalog/`](https://github.com/ChrisAdkin8/tf-analyze/tree/main/catalog)).

**209 rules** across 8 sections. Click any rule ID for the full description, remediation, and verification.

---

## cicd (1)

| Rule | Urgency | Title |
|------|---------|-------|
| [`CI-TEST-001`](./CI-TEST-001.md) | LOW | Module has no Terraform test files |

## dry (1)

| Rule | Urgency | Title |
|------|---------|-------|
| [`MOD-STALE-001`](./MOD-STALE-001.md) | LOW | Registry module is significantly behind latest version |

## module (4)

| Rule | Urgency | Title |
|------|---------|-------|
| [`MOD-PIN-001`](./MOD-PIN-001.md) | HIGH | Module source not pinned |
| [`MOD-SUPPLY-001`](./MOD-SUPPLY-001.md) | HIGH | Module pinned to mutable git ref (main or master) |
| [`MOD-SUPPLY-003`](./MOD-SUPPLY-003.md) | HIGH | Registry module missing version constraint |
| [`MOD-SUPPLY-002`](./MOD-SUPPLY-002.md) | LOW | Module uses raw git source instead of registry |

## ops (7)

| Rule | Urgency | Title |
|------|---------|-------|
| [`OPS-ENV-001`](./OPS-ENV-001.md) | HIGH | Prod-scoped resource lacks deletion_protection |
| [`COST-AWS-RISK-001`](./COST-AWS-RISK-001.md) | MEDIUM | AWS resource missing cost control |
| [`COST-GCP-RISK-001`](./COST-GCP-RISK-001.md) | MEDIUM | Expensive resource without cost control |
| [`OPS-AWS-TAGS-001`](./OPS-AWS-TAGS-001.md) | MEDIUM | AWS resource missing tags |
| [`OPS-AZURE-TAGS-001`](./OPS-AZURE-TAGS-001.md) | MEDIUM | Azure resource missing tags |
| [`OPS-GCP-LABELS-001`](./OPS-GCP-LABELS-001.md) | MEDIUM | GCP resource missing labels block |
| [`OPS-AWS-CWL-001`](./OPS-AWS-CWL-001.md) | LOW | CloudWatch log group has no retention policy |

## robustness (40)

| Rule | Urgency | Title |
|------|---------|-------|
| [`ROB-AWS-BACKEND-001`](./ROB-AWS-BACKEND-001.md) | HIGH | Terraform S3 backend missing DynamoDB state locking |
| [`ROB-AWS-DDB-001`](./ROB-AWS-DDB-001.md) | HIGH | DynamoDB table missing deletion protection |
| [`ROB-AWS-LIFECYCLE-001`](./ROB-AWS-LIFECYCLE-001.md) | HIGH | Stateful AWS resource missing lifecycle.prevent_destroy |
| [`ROB-AWS-LIFECYCLE-002`](./ROB-AWS-LIFECYCLE-002.md) | HIGH | S3 bucket has force_destroy enabled |
| [`ROB-AWS-RDS-001`](./ROB-AWS-RDS-001.md) | HIGH | RDS instance or Aurora cluster backup retention disabled |
| [`ROB-AWS-RDS-002`](./ROB-AWS-RDS-002.md) | HIGH | RDS instance or Aurora cluster skips final snapshot on deletion |
| [`ROB-AWS-RDS-003`](./ROB-AWS-RDS-003.md) | HIGH | RDS instance or Aurora cluster missing deletion protection |
| [`ROB-AZURE-LIFECYCLE-001`](./ROB-AZURE-LIFECYCLE-001.md) | HIGH | Stateful Azure resource missing lifecycle.prevent_destroy |
| [`ROB-COUNTREF-002`](./ROB-COUNTREF-002.md) | HIGH | Unguarded indexed reference to count = length(...) resource |
| [`ROB-DRIFT-001`](./ROB-DRIFT-001.md) | HIGH | Resource uses ignore_changes = all |
| [`ROB-GCP-LIFECYCLE-001`](./ROB-GCP-LIFECYCLE-001.md) | HIGH | Stateful resource missing lifecycle.prevent_destroy |
| [`ROB-GCP-LIFECYCLE-002`](./ROB-GCP-LIFECYCLE-002.md) | HIGH | Stateful resource has force_destroy=true |
| [`ROB-PROVIDER-ALIAS-001`](./ROB-PROVIDER-ALIAS-001.md) | HIGH | Module references provider alias that is not declared |
| [`ROB-VERSION-003`](./ROB-VERSION-003.md) | HIGH | required_providers entry missing version constraint |
| [`ROB-AWS-ALB-001`](./ROB-AWS-ALB-001.md) | MEDIUM | Load balancer deletion protection disabled |
| [`ROB-AWS-BACKUP-001`](./ROB-AWS-BACKUP-001.md) | MEDIUM | No AWS Backup plan defined |
| [`ROB-AWS-DDB-002`](./ROB-AWS-DDB-002.md) | MEDIUM | DynamoDB table missing point-in-time recovery |
| [`ROB-AWS-REDSHIFT-001`](./ROB-AWS-REDSHIFT-001.md) | MEDIUM | Redshift cluster has no automated snapshot retention |
| [`ROB-AWS-S3-001`](./ROB-AWS-S3-001.md) | MEDIUM | S3 bucket versioning disabled or suspended |
| [`ROB-AWS-SECRETSMANAGER-001`](./ROB-AWS-SECRETSMANAGER-001.md) | MEDIUM | Secrets Manager secret has no automatic rotation configured |
| [`ROB-AZURE-SQL-001`](./ROB-AZURE-SQL-001.md) | MEDIUM | Azure SQL database missing short-term backup retention policy |
| [`ROB-AZURE-STORAGE-001`](./ROB-AZURE-STORAGE-001.md) | MEDIUM | Azure storage account missing blob soft delete |
| [`ROB-BACKEND-001`](./ROB-BACKEND-001.md) | MEDIUM | Inconsistent backend configuration across root modules |
| [`ROB-CHECK-001`](./ROB-CHECK-001.md) | MEDIUM | TF 1.5+ check block missing assert |
| [`ROB-COUNTREF-001`](./ROB-COUNTREF-001.md) | MEDIUM | Unguarded reference to count-conditional resource |
| [`ROB-FOREACH-001`](./ROB-FOREACH-001.md) | MEDIUM | for_each over list instead of map/set |
| [`ROB-PRECONDITION-001`](./ROB-PRECONDITION-001.md) | MEDIUM | Precondition or postcondition missing error_message |
| [`ROB-REMOTESTATE-001`](./ROB-REMOTESTATE-001.md) | MEDIUM | terraform_remote_state data source couples modules implicitly |
| [`ROB-VALIDATION-001`](./ROB-VALIDATION-001.md) | MEDIUM | Variable accepts dangerous input without validation block |
| [`ROB-VALIDATION-002`](./ROB-VALIDATION-002.md) | MEDIUM | Variable typed as bare any |
| [`ROB-VERSION-001`](./ROB-VERSION-001.md) | MEDIUM | required_version floor too old for skill assumptions |
| [`STK-GCP-DEPRECATION-001`](./STK-GCP-DEPRECATION-001.md) | MEDIUM | Resource uses deprecated argument |
| [`ROB-COUNT-001`](./ROB-COUNT-001.md) | LOW | Boolean count pattern instead of for_each |
| [`ROB-COUNT-002`](./ROB-COUNT-002.md) | LOW | Module mixes count-based and for_each-based resources |
| [`ROB-MOVED-001`](./ROB-MOVED-001.md) | LOW | Stale moved block may need cleanup |
| [`ROB-PROVIDER-ALIAS-002`](./ROB-PROVIDER-ALIAS-002.md) | LOW | Provider alias declared but never referenced |
| [`ROB-REMOVED-001`](./ROB-REMOVED-001.md) | LOW | Stale removed block may need cleanup |
| [`ROB-UNUSED-001`](./ROB-UNUSED-001.md) | LOW | Declared variable is never referenced |
| [`ROB-UNUSED-002`](./ROB-UNUSED-002.md) | LOW | Declared output is never consumed by any caller |
| [`ROB-VERSION-002`](./ROB-VERSION-002.md) | LOW | Submodule directory has no required_version |

## security (116)

| Rule | Urgency | Title |
|------|---------|-------|
| [`SEC-AWS-CLOUDTRAIL-001`](./SEC-AWS-CLOUDTRAIL-001.md) | CRITICAL | CloudTrail not enabled for all regions |
| [`SEC-AWS-IAM-002`](./SEC-AWS-IAM-002.md) | CRITICAL | IAM assume role policy with wildcard Principal |
| [`SEC-AWS-IAM-JSON-002`](./SEC-AWS-IAM-JSON-002.md) | CRITICAL | Inline IAM policy JSON grants wildcard `iam:*` action |
| [`SEC-AWS-IAM-JSON-003`](./SEC-AWS-IAM-JSON-003.md) | CRITICAL | Inline IAM policy JSON grants `Action: \"*\"` AND `Resource: \"*\"` |
| [`SEC-AWS-IAM-JSON-004`](./SEC-AWS-IAM-JSON-004.md) | CRITICAL | Inline IAM policy JSON has public principal (`Principal: \"*\"`) |
| [`SEC-AWS-IAM-POLICY-002`](./SEC-AWS-IAM-POLICY-002.md) | CRITICAL | IAM policy document grants wildcard `iam:*` actions |
| [`SEC-AWS-IAM-POLICY-004`](./SEC-AWS-IAM-POLICY-004.md) | CRITICAL | IAM policy document grants principal `identifiers = [\"*\"]` (public) |
| [`SEC-AWS-IAM-POLICY-005`](./SEC-AWS-IAM-POLICY-005.md) | CRITICAL | IAM policy grants both `actions = [\"*\"]` and `resources = [\"*\"]` |
| [`SEC-GCP-IAM-002`](./SEC-GCP-IAM-002.md) | CRITICAL | Public IAM binding (allUsers / allAuthenticatedUsers) |
| [`SEC-GCP-NETWORK-001`](./SEC-GCP-NETWORK-001.md) | CRITICAL | SSH (tcp:22) exposed to 0.0.0.0/0 |
| [`SEC-GCP-NETWORK-002`](./SEC-GCP-NETWORK-002.md) | CRITICAL | RDP (tcp:3389) exposed to 0.0.0.0/0 |
| [`SEC-GCP-NETWORK-004`](./SEC-GCP-NETWORK-004.md) | CRITICAL | GCP firewall rule exposes database or cache port to 0.0.0.0/0 |
| [`SEC-K8S-HELM-002`](./SEC-K8S-HELM-002.md) | CRITICAL | helm_release sets `securityContext.privileged=true` |
| [`SEC-K8S-RBAC-001`](./SEC-K8S-RBAC-001.md) | CRITICAL | ClusterRoleBinding grants cluster-admin |
| [`SEC-SECRETS-001`](./SEC-SECRETS-001.md) | CRITICAL | Hardcoded credential or API key in Terraform source |
| [`SEC-STATE-001`](./SEC-STATE-001.md) | CRITICAL | .tfstate file committed to the repository |
| [`INT-INTENT-003`](./INT-INTENT-003.md) | HIGH | Prod-tagged resource has deletion_protection=false |
| [`INT-INTENT-004`](./INT-INTENT-004.md) | HIGH | Prod-tagged resource has force_destroy=true |
| [`SEC-AWS-ACCESSKEY-001`](./SEC-AWS-ACCESSKEY-001.md) | HIGH | Long-lived IAM access key created for a user |
| [`SEC-AWS-CLOUDFRONT-001`](./SEC-AWS-CLOUDFRONT-001.md) | HIGH | CloudFront distribution serves HTTP without redirect |
| [`SEC-AWS-CLOUDTRAIL-002`](./SEC-AWS-CLOUDTRAIL-002.md) | HIGH | CloudTrail log file integrity validation disabled |
| [`SEC-AWS-COGNITO-001`](./SEC-AWS-COGNITO-001.md) | HIGH | Cognito user pool MFA not enabled |
| [`SEC-AWS-DOCDB-001`](./SEC-AWS-DOCDB-001.md) | HIGH | DocumentDB cluster storage not encrypted |
| [`SEC-AWS-EBS-001`](./SEC-AWS-EBS-001.md) | HIGH | EBS volume not encrypted |
| [`SEC-AWS-ECR-001`](./SEC-AWS-ECR-001.md) | HIGH | ECR repository missing scan-on-push |
| [`SEC-AWS-ECS-001`](./SEC-AWS-ECS-001.md) | HIGH | ECS task definition exposes secrets in plaintext environment variables |
| [`SEC-AWS-ECS-002`](./SEC-AWS-ECS-002.md) | HIGH | ECS task definition runs a privileged container |
| [`SEC-AWS-ELASTICACHE-001`](./SEC-AWS-ELASTICACHE-001.md) | HIGH | ElastiCache replication group missing encryption |
| [`SEC-AWS-ES-001`](./SEC-AWS-ES-001.md) | HIGH | OpenSearch / Elasticsearch domain missing encryption at rest |
| [`SEC-AWS-ES-002`](./SEC-AWS-ES-002.md) | HIGH | OpenSearch / Elasticsearch domain missing node-to-node encryption |
| [`SEC-AWS-ES-003`](./SEC-AWS-ES-003.md) | HIGH | OpenSearch domain missing fine-grained access control |
| [`SEC-AWS-GUARDDUTY-001`](./SEC-AWS-GUARDDUTY-001.md) | HIGH | GuardDuty detector not provisioned |
| [`SEC-AWS-IAM-001`](./SEC-AWS-IAM-001.md) | HIGH | IAM policy with wildcard resource |
| [`SEC-AWS-IAM-JSON-001`](./SEC-AWS-IAM-JSON-001.md) | HIGH | Inline IAM policy JSON grants wildcard `Action: \"*\"` |
| [`SEC-AWS-IAM-POLICY-001`](./SEC-AWS-IAM-POLICY-001.md) | HIGH | IAM policy document grants wildcard `actions = [\"*\"]` |
| [`SEC-AWS-IAM-POLICY-003`](./SEC-AWS-IAM-POLICY-003.md) | HIGH | IAM policy document grants wildcard `resources = [\"*\"]` |
| [`SEC-AWS-KMS-001`](./SEC-AWS-KMS-001.md) | HIGH | KMS key rotation disabled |
| [`SEC-AWS-LB-LISTENER-001`](./SEC-AWS-LB-LISTENER-001.md) | HIGH | ALB listener serves plain HTTP without redirect |
| [`SEC-AWS-MSK-001`](./SEC-AWS-MSK-001.md) | HIGH | MSK cluster allows unencrypted client-broker traffic |
| [`SEC-AWS-NEPTUNE-001`](./SEC-AWS-NEPTUNE-001.md) | HIGH | Neptune cluster storage not encrypted |
| [`SEC-AWS-RDS-001`](./SEC-AWS-RDS-001.md) | HIGH | RDS instance or Aurora cluster publicly accessible |
| [`SEC-AWS-RDS-002`](./SEC-AWS-RDS-002.md) | HIGH | RDS instance or Aurora cluster storage not encrypted |
| [`SEC-AWS-REDSHIFT-001`](./SEC-AWS-REDSHIFT-001.md) | HIGH | Redshift cluster encryption disabled |
| [`SEC-AWS-S3-001`](./SEC-AWS-S3-001.md) | HIGH | S3 bucket missing server-side encryption configuration |
| [`SEC-AWS-S3-PUBLIC-BLOCK-001`](./SEC-AWS-S3-PUBLIC-BLOCK-001.md) | HIGH | S3 bucket missing public access block |
| [`SEC-AWS-SG-001`](./SEC-AWS-SG-001.md) | HIGH | Security group allows ingress from 0.0.0.0/0 |
| [`SEC-AWS-SNS-001`](./SEC-AWS-SNS-001.md) | HIGH | SNS topic missing KMS encryption |
| [`SEC-AWS-SQS-001`](./SEC-AWS-SQS-001.md) | HIGH | SQS queue missing server-side encryption |
| [`SEC-AWS-SSM-001`](./SEC-AWS-SSM-001.md) | HIGH | SSM Parameter Store parameter not encrypted as SecureString |
| [`SEC-AWS-SSRF-001`](./SEC-AWS-SSRF-001.md) | HIGH | EC2 instance metadata service v1 enabled (IMDSv2 not enforced) |
| [`SEC-AWS-VPC-FLOWLOGS-001`](./SEC-AWS-VPC-FLOWLOGS-001.md) | HIGH | AWS VPC missing flow log resource |
| [`SEC-AZURE-ACR-001`](./SEC-AZURE-ACR-001.md) | HIGH | Azure Container Registry admin account enabled |
| [`SEC-AZURE-AKS-001`](./SEC-AZURE-AKS-001.md) | HIGH | AKS cluster RBAC disabled |
| [`SEC-AZURE-AKS-002`](./SEC-AZURE-AKS-002.md) | HIGH | AKS cluster missing network policy |
| [`SEC-AZURE-KV-001`](./SEC-AZURE-KV-001.md) | HIGH | Azure Key Vault missing purge protection or soft delete |
| [`SEC-AZURE-KV-002`](./SEC-AZURE-KV-002.md) | HIGH | Key Vault missing network ACL deny-by-default |
| [`SEC-AZURE-LOGGING-001`](./SEC-AZURE-LOGGING-001.md) | HIGH | Azure Key Vault missing diagnostic settings |
| [`SEC-AZURE-MONITOR-001`](./SEC-AZURE-MONITOR-001.md) | HIGH | Azure subscription missing activity log diagnostic setting |
| [`SEC-AZURE-RBAC-001`](./SEC-AZURE-RBAC-001.md) | HIGH | Azure role assignment scope is subscription-wide |
| [`SEC-AZURE-REDIS-001`](./SEC-AZURE-REDIS-001.md) | HIGH | Azure Redis Cache allows non-TLS connections |
| [`SEC-AZURE-SQL-001`](./SEC-AZURE-SQL-001.md) | HIGH | Azure SQL Server has no Azure AD administrator configured |
| [`SEC-AZURE-SQL-002`](./SEC-AZURE-SQL-002.md) | HIGH | Azure SQL Server firewall rule allows access from all IPs |
| [`SEC-AZURE-STORAGE-001`](./SEC-AZURE-STORAGE-001.md) | HIGH | Azure storage account allows non-HTTPS traffic |
| [`SEC-AZURE-STORAGE-002`](./SEC-AZURE-STORAGE-002.md) | HIGH | Azure storage account allows public blob access |
| [`SEC-AZURE-VM-001`](./SEC-AZURE-VM-001.md) | HIGH | Linux VM allows SSH password authentication |
| [`SEC-AZURE-WEBAPP-002`](./SEC-AZURE-WEBAPP-002.md) | HIGH | App Service / Function App HTTPS not enforced |
| [`SEC-DATASOURCE-002`](./SEC-DATASOURCE-002.md) | HIGH | data.external program takes user-controlled input |
| [`SEC-GCP-BUCKET-001`](./SEC-GCP-BUCKET-001.md) | HIGH | GCS bucket missing public_access_prevention=enforced |
| [`SEC-GCP-CLOUDRUN-001`](./SEC-GCP-CLOUDRUN-001.md) | HIGH | Cloud Run service allows all ingress traffic |
| [`SEC-GCP-COMPUTE-PUBLIC-IP-001`](./SEC-GCP-COMPUTE-PUBLIC-IP-001.md) | HIGH | Compute instance has a public IP via access_config |
| [`SEC-GCP-COMPUTE-SA-001`](./SEC-GCP-COMPUTE-SA-001.md) | HIGH | Compute instance uses default Compute Engine service account |
| [`SEC-GCP-GKE-NETWORK-POLICY-001`](./SEC-GCP-GKE-NETWORK-POLICY-001.md) | HIGH | GKE cluster missing network_policy enforcement |
| [`SEC-GCP-IAM-001`](./SEC-GCP-IAM-001.md) | HIGH | Project-level binding of overly broad role |
| [`SEC-GCP-IAM-003`](./SEC-GCP-IAM-003.md) | HIGH | Member has both project-level and resource-level IAM grants |
| [`SEC-GCP-LOGGING-001`](./SEC-GCP-LOGGING-001.md) | HIGH | Cloud Audit Logs not configured |
| [`SEC-GCP-NETWORK-003`](./SEC-GCP-NETWORK-003.md) | HIGH | VPC subnet missing flow logs |
| [`SEC-GCP-REDIS-001`](./SEC-GCP-REDIS-001.md) | HIGH | Cloud Memorystore Redis instance AUTH disabled |
| [`SEC-GCP-REDIS-002`](./SEC-GCP-REDIS-002.md) | HIGH | Cloud Memorystore Redis instance transit encryption disabled |
| [`SEC-GCP-SA-KEY-001`](./SEC-GCP-SA-KEY-001.md) | HIGH | GCP service account key created in Terraform |
| [`SEC-GCP-SQL-PUBLIC-001`](./SEC-GCP-SQL-PUBLIC-001.md) | HIGH | Cloud SQL instance permits public IPv4 |
| [`SEC-K8S-HELM-001`](./SEC-K8S-HELM-001.md) | HIGH | helm_release sets `service.type=LoadBalancer` (publicly exposed) |
| [`SEC-K8S-NETPOL-001`](./SEC-K8S-NETPOL-001.md) | HIGH | kubernetes_network_policy absent for the corpus |
| [`SEC-K8S-PSA-001`](./SEC-K8S-PSA-001.md) | HIGH | kubernetes_namespace missing Pod Security Admission label |
| [`SEC-PROVISIONER-001`](./SEC-PROVISIONER-001.md) | HIGH | Provisioner block used for shell execution |
| [`SEC-SENSITIVE-001`](./SEC-SENSITIVE-001.md) | HIGH | Sensitive output not marked sensitive=true |
| [`SEC-SENSITIVE-002`](./SEC-SENSITIVE-002.md) | HIGH | Sensitive marker dropped at module boundary |
| [`SEC-SENSITIVE-003`](./SEC-SENSITIVE-003.md) | HIGH | Sensitive variable passed to templatefile() |
| [`INT-INTENT-001`](./INT-INTENT-001.md) | MEDIUM | Security-intent variable defaults to false/null/0 |
| [`INT-INTENT-002`](./INT-INTENT-002.md) | MEDIUM | Variable description says 'must be true' but has no validation block |
| [`SEC-AWS-ALB-001`](./SEC-AWS-ALB-001.md) | MEDIUM | Load balancer access logs disabled |
| [`SEC-AWS-APIGW-001`](./SEC-AWS-APIGW-001.md) | MEDIUM | API Gateway stage missing access log destination |
| [`SEC-AWS-ATHENA-001`](./SEC-AWS-ATHENA-001.md) | MEDIUM | Athena workgroup results not encrypted |
| [`SEC-AWS-BACKUP-001`](./SEC-AWS-BACKUP-001.md) | MEDIUM | Backup vault uses AWS-managed key (no CMK) |
| [`SEC-AWS-CLOUDFRONT-002`](./SEC-AWS-CLOUDFRONT-002.md) | MEDIUM | CloudFront distribution missing access logging |
| [`SEC-AWS-CWL-001`](./SEC-AWS-CWL-001.md) | MEDIUM | CloudWatch log group not encrypted with KMS CMK |
| [`SEC-AWS-DDB-001`](./SEC-AWS-DDB-001.md) | MEDIUM | DynamoDB table not using customer-managed KMS key for encryption |
| [`SEC-AWS-ECR-002`](./SEC-AWS-ECR-002.md) | MEDIUM | ECR repository missing image lifecycle policy |
| [`SEC-AWS-IAM-003`](./SEC-AWS-IAM-003.md) | MEDIUM | IAM account password policy is not configured or too weak |
| [`SEC-AWS-IAM-POLICY-006`](./SEC-AWS-IAM-POLICY-006.md) | MEDIUM | IAM policy uses `not_actions` or `not_resources` |
| [`SEC-AWS-KINESIS-001`](./SEC-AWS-KINESIS-001.md) | MEDIUM | Kinesis Data Stream not encrypted with KMS |
| [`SEC-AWS-MSK-002`](./SEC-AWS-MSK-002.md) | MEDIUM | MSK cluster does not use CMK for encryption at rest |
| [`SEC-AWS-S3-LOGGING-001`](./SEC-AWS-S3-LOGGING-001.md) | MEDIUM | S3 bucket missing server access logging |
| [`SEC-AWS-SECRETSMANAGER-001`](./SEC-AWS-SECRETSMANAGER-001.md) | MEDIUM | Secrets Manager secret uses AWS-managed key (no CMK) |
| [`SEC-AWS-SECURITYHUB-001`](./SEC-AWS-SECURITYHUB-001.md) | MEDIUM | Security Hub not enabled |
| [`SEC-AWS-WAF-001`](./SEC-AWS-WAF-001.md) | MEDIUM | WAFv2 web ACL missing logging configuration |
| [`SEC-AZURE-EVENTHUB-001`](./SEC-AZURE-EVENTHUB-001.md) | MEDIUM | Event Hub namespace does not use CMK encryption |
| [`SEC-AZURE-KV-003`](./SEC-AZURE-KV-003.md) | MEDIUM | Azure Key Vault key missing rotation policy |
| [`SEC-AZURE-MI-001`](./SEC-AZURE-MI-001.md) | MEDIUM | Azure user-assigned identity with no role assignment (orphan UAMI) |
| [`SEC-AZURE-SERVICEBUS-001`](./SEC-AZURE-SERVICEBUS-001.md) | MEDIUM | Service Bus namespace does not use CMK encryption |
| [`SEC-AZURE-WEBAPP-001`](./SEC-AZURE-WEBAPP-001.md) | MEDIUM | Azure App Service / Function App missing IP access restrictions |
| [`SEC-DATASOURCE-001`](./SEC-DATASOURCE-001.md) | MEDIUM | External or HTTP data source executes at plan time |
| [`SEC-EPHEMERAL-001`](./SEC-EPHEMERAL-001.md) | MEDIUM | Vault secret data source should use ephemeral on Terraform 1.10+ |
| [`SEC-GCP-BUCKET-002`](./SEC-GCP-BUCKET-002.md) | MEDIUM | GCS bucket missing uniform_bucket_level_access |
| [`SEC-GCP-COMPUTE-DISK-001`](./SEC-GCP-COMPUTE-DISK-001.md) | MEDIUM | GCP compute disk not encrypted with CSEK/CMEK |
| [`SEC-GCP-COMPUTE-SHIELDED-001`](./SEC-GCP-COMPUTE-SHIELDED-001.md) | MEDIUM | GCP Compute instance missing shielded instance configuration |
| [`SEC-PROVIDER-001`](./SEC-PROVIDER-001.md) | MEDIUM | Provider version constraint missing upper bound |

## stack (39)

| Rule | Urgency | Title |
|------|---------|-------|
| [`STK-AWS-EKS-001`](./STK-AWS-EKS-001.md) | HIGH | EKS cluster API endpoint private access not enabled |
| [`STK-AWS-EKS-002`](./STK-AWS-EKS-002.md) | HIGH | EKS cluster control plane logging not enabled |
| [`STK-AWS-EKS-003`](./STK-AWS-EKS-003.md) | HIGH | EKS cluster Kubernetes Secrets not encrypted with KMS |
| [`STK-AWS-EKS-005`](./STK-AWS-EKS-005.md) | HIGH | EKS cluster missing audit log type in enabled_cluster_log_types |
| [`STK-AWS-LAMBDA-001`](./STK-AWS-LAMBDA-001.md) | HIGH | Lambda function uses end-of-life runtime |
| [`STK-AWS-LAUNCH-TEMPLATE-001`](./STK-AWS-LAUNCH-TEMPLATE-001.md) | HIGH | EC2 launch template does not enforce IMDSv2 |
| [`STK-AWS-RDS-004`](./STK-AWS-RDS-004.md) | HIGH | RDS instance uses end-of-life database engine version |
| [`STK-AZURE-AKS-003`](./STK-AZURE-AKS-003.md) | HIGH | AKS cluster workload identity not enabled |
| [`STK-AZURE-AKS-004`](./STK-AZURE-AKS-004.md) | HIGH | AKS cluster API server is publicly accessible |
| [`STK-AZURE-DB-001`](./STK-AZURE-DB-001.md) | HIGH | Azure MySQL/PostgreSQL server missing SSL enforcement |
| [`STK-AZURE-NSG-001`](./STK-AZURE-NSG-001.md) | HIGH | Azure NSG rule open to the internet on sensitive ports |
| [`STK-AZURE-NSG-FLOWLOG-001`](./STK-AZURE-NSG-FLOWLOG-001.md) | HIGH | Azure NSG missing flow log resource |
| [`STK-AZURE-SQL-001`](./STK-AZURE-SQL-001.md) | HIGH | Azure MySQL/PostgreSQL single server is deprecated |
| [`STK-AZURE-SQL-TDE-001`](./STK-AZURE-SQL-TDE-001.md) | HIGH | Azure SQL Database missing transparent data encryption resource |
| [`STK-GCP-BIGQUERY-001`](./STK-GCP-BIGQUERY-001.md) | HIGH | BigQuery dataset missing default CMEK |
| [`STK-GCP-CLOUDSQL-001`](./STK-GCP-CLOUDSQL-001.md) | HIGH | Cloud SQL instance missing backup_configuration |
| [`STK-GCP-CLOUDSQL-003`](./STK-GCP-CLOUDSQL-003.md) | HIGH | Cloud SQL instance missing deletion protection |
| [`STK-GCP-CLOUDSQL-004`](./STK-GCP-CLOUDSQL-004.md) | HIGH | Cloud SQL instance does not require SSL connections |
| [`STK-GCP-CLOUDSQL-005`](./STK-GCP-CLOUDSQL-005.md) | HIGH | Cloud SQL instance uses end-of-life database version |
| [`STK-GCP-DNS-001`](./STK-GCP-DNS-001.md) | HIGH | Cloud DNS managed zone missing DNSSEC |
| [`STK-GCP-GCS-LOGGING-001`](./STK-GCP-GCS-LOGGING-001.md) | HIGH | GCS bucket logging target lacks public_access_prevention |
| [`STK-GCP-GKE-001`](./STK-GCP-GKE-001.md) | HIGH | GKE cluster missing private nodes |
| [`STK-GCP-GKE-002`](./STK-GCP-GKE-002.md) | HIGH | GKE cluster missing Workload Identity |
| [`STK-GCP-GKE-003`](./STK-GCP-GKE-003.md) | HIGH | GKE cluster missing application-layer secrets encryption |
| [`STK-GCP-GKE-004`](./STK-GCP-GKE-004.md) | HIGH | GKE cluster missing master authorized networks |
| [`STK-GCP-GKE-NODEPOOL-001`](./STK-GCP-GKE-NODEPOOL-001.md) | HIGH | GKE node pool missing shielded-instance hardening |
| [`STK-GCP-KMS-001`](./STK-GCP-KMS-001.md) | HIGH | KMS crypto key missing rotation period |
| [`STK-GCP-KMS-LOCATION-001`](./STK-GCP-KMS-LOCATION-001.md) | HIGH | CMEK consumer location mismatches KMS key ring location |
| [`STK-AWS-ECS-001`](./STK-AWS-ECS-001.md) | MEDIUM | ECS cluster Container Insights not configured |
| [`STK-AWS-EKS-004`](./STK-AWS-EKS-004.md) | MEDIUM | EKS cluster missing OIDC provider for IRSA |
| [`STK-AWS-LAMBDA-002`](./STK-AWS-LAMBDA-002.md) | MEDIUM | Lambda function missing dead-letter queue configuration |
| [`STK-AWS-ROUTE53-001`](./STK-AWS-ROUTE53-001.md) | MEDIUM | Route 53 hosted zone missing DNSSEC signing |
| [`STK-AZURE-AKS-005`](./STK-AZURE-AKS-005.md) | MEDIUM | AKS cluster API server missing authorized IP ranges |
| [`STK-AZURE-STORAGE-001`](./STK-AZURE-STORAGE-001.md) | MEDIUM | Azure storage account missing blob versioning |
| [`STK-DEPRECATION-002`](./STK-DEPRECATION-002.md) | MEDIUM | Deprecated data source: data.template_file |
| [`STK-GCP-ARTIFACT-001`](./STK-GCP-ARTIFACT-001.md) | MEDIUM | Artifact Registry repository missing customer-managed encryption key |
| [`STK-GCP-BUCKET-001`](./STK-GCP-BUCKET-001.md) | MEDIUM | GCS bucket missing versioning |
| [`STK-GCP-PUBSUB-001`](./STK-GCP-PUBSUB-001.md) | MEDIUM | Pub/Sub topic missing customer-managed encryption key |
| [`STK-AWS-LAMBDA-003`](./STK-AWS-LAMBDA-003.md) | LOW | Lambda function active X-Ray tracing not configured |

## style (1)

| Rule | Urgency | Title |
|------|---------|-------|
| [`STYLE-DESC-001`](./STYLE-DESC-001.md) | LOW | Variable or output missing description |

