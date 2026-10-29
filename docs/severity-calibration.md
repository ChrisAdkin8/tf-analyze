# Severity calibration log

This document records explicit calibration decisions for `default_urgency`
in `catalog/*.yaml`. The intent is that severity is *defensible*, not
arbitrary — when a rule's urgency is changed, the rationale lives here so
future maintainers can see why.

## Methodology

A rule's `default_urgency` is set by considering:

1. **Worst-case consequence** under the catalogue's `blast_radius`
   classification. A misconfiguration that loses one row of test data is
   not a CRITICAL even if it touches sensitive data; the same
   misconfiguration on a production credential store is.
2. **Exploitability**. Rules that detect a *direct* path to compromise
   (no chained prerequisites, no privileged context required) rank
   higher than rules that need an attacker to already hold a foothold.
3. **Detection-evasion impact**. Rules that disable observability
   (CloudTrail, VPC Flow Logs, GuardDuty) rank one tier above the
   median because they make every other rule less detectable in
   production.
4. **Industry baselines**. Where checkov / tfsec / Prowler ship a
   similar rule, we calibrate to the median; where we diverge, the
   reason is recorded below.

## Tiers

| Urgency  | Meaning                                                                 |
|----------|-------------------------------------------------------------------------|
| CRITICAL | Immediate-blast: data exposure, privilege escalation, or audit blackout |
| HIGH     | Direct security boundary breach with realistic exploit path             |
| MEDIUM   | Defense-in-depth gap; exploitation needs a chained vulnerability        |
| LOW      | Style / hygiene / advisory                                              |
| INFO     | Information-only; never CI-blocking                                     |

## Round-23 calibration adjustments

| Rule ID                  | From | To       | Rationale                                                                                                                                                              |
|--------------------------|------|----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| SEC-AWS-CLOUDTRAIL-001   | HIGH | CRITICAL | Single-region CloudTrail = audit blackout for every other region. Realistic attacker move during incident response evasion. CIS Benchmark 3.1 also treats as critical. |
| SEC-AWS-IAM-POLICY-006   | HIGH | MEDIUM   | `not_actions` / `not_resources` is a code-smell, not a guaranteed exposure. Engine already excludes `Effect = "Deny"`, so positives are advisory.                      |

## 2026-10-28 calibration adjustments

Goal: a minimal, secure module passes `--fail-on HIGH`. Before, a
private, versioned S3 bucket with a full public access block still failed
on two HIGHs (`ROB-AWS-LIFECYCLE-001`, `SEC-AWS-S3-001`), and 55% of
active rules were HIGH or CRITICAL. Rules in the `robustness` section are
now at most MEDIUM (`tests/test_severity_calibration.py` keeps it so):
they cover data loss and plan/apply breakage, not a security boundary.
Free-text `is_production_environment` escalations (judgement-pass
guidance; the engine ignores them) now go one tier up, not to CRITICAL.

| Rule ID | From | To | Rationale |
|---|---|---|---|
| ROB-AWS-LIFECYCLE-001, ROB-AZURE-LIFECYCLE-001, ROB-GCP-LIFECYCLE-001 | HIGH | LOW | `prevent_destroy` is a Terraform workflow guard. The real risk, deleting a stateful resource, is covered by the deletion-protection rules. At HIGH it put a HIGH on every bucket, database and table. |
| SEC-AWS-S3-001 | HIGH | LOW | Since January 2023 S3 encrypts every new object with SSE-S3, so a bucket without an encryption resource is encrypted at rest. What is left is the SSE-S3 vs KMS choice: advisory. |
| SEC-AWS-S3-PUBLIC-BLOCK-001 | HIGH | MEDIUM | Overturns the standing decision below. Since April 2023 new buckets have Block Public Access on and ACLs off by default, so a missing block resource is a defence-in-depth gap, not an exposure. An actually public ACL or grant is `SEC-AWS-S3-PUBLIC-001` (HIGH). |
| ROB-AWS-RDS-001, ROB-AWS-RDS-002, ROB-AWS-RDS-003, ROB-AWS-DDB-001, STK-GCP-CLOUDSQL-001, STK-GCP-CLOUDSQL-003 | HIGH | MEDIUM | Backups, final snapshot and deletion protection: data loss after a mistake or a compromise, not a way in. |
| ROB-AWS-LIFECYCLE-002, ROB-GCP-LIFECYCLE-002 | HIGH | MEDIUM | `force_destroy` lets `terraform destroy` empty a bucket: data loss, not exposure. |
| ROB-COUNTNAME-001, ROB-COUNTREF-002, ROB-FOREACH-002, ROB-DRIFT-001, ROB-PROVIDER-ALIAS-001, ROB-VERSION-003, ROB-AWS-BACKEND-001 | HIGH | MEDIUM | Plan/apply correctness (re-keying, drift hidden by `ignore_changes = all`, an undeclared alias, unpinned providers, no state lock): real outages, no security boundary. |

The HIGH `security` and `stack` rules were swept next (below).

## 2026-10-28 security and stack sweep

Every active HIGH rule in the `security` (102) and `stack` (41) sections
was checked against the tiers above: 143 rules. 109 move down
(107 to MEDIUM, 2 to LOW) and 34 stay HIGH. No finding appears or
disappears. Active rules at HIGH or CRITICAL go from 175 of 352 (50%) to
66 (19%).

How the line was drawn:

- **HIGH** stays for a way in with no foothold needed: world-open admin
  or database ports, anonymous or public data stores, wildcard IAM,
  secrets in code / state / user data, disabled auth, and the
  account-wide audit trail (point 3 above).
- **MEDIUM** for defence in depth: encryption in transit (reading the
  traffic needs a network position), encryption at rest (reading disks
  or snapshots needs access the attacker does not have yet), WAF,
  network policies, private endpoints for services that still need
  credentials, per-resource logs and threat detection, key rotation,
  supply-chain hygiene, and end-of-life runtimes (harm needs an
  unpatched, reachable bug).
- Point 3 (detection evasion) covers the account-wide audit trail and
  explicit opt-outs of threat detection. Flow logs and per-resource
  diagnostic logs are telemetry and are MEDIUM, as in Prowler and CIS
  Level 2. Rules that fire because a repo does not *declare* an
  account-wide service (GuardDuty, Defender) are MEDIUM: those services
  are usually turned on org-wide from a security account.
- **LOW** where the cloud already encrypts by default and the only
  question is whose key (as with `SEC-AWS-S3-001`).
- Data-store at-rest encryption rules gain a free-text
  `is_production_environment` escalation back to HIGH.
  `SEC-AZURE-DEFENDER-001` gains an engine-evaluated escalation: an
  explicit `tier = "Free"` is still HIGH.

| Rule ID | From | To | Rationale |
|---|---|---|---|
| INT-INTENT-003 | HIGH | MEDIUM | Deletion protection: data loss after a mistake, not a way in. Same tier as `ROB-AWS-RDS-003`. |
| INT-INTENT-004 | HIGH | MEDIUM | `force_destroy` on a prod resource: data loss on destroy, not exposure. Same tier as `ROB-AWS-LIFECYCLE-002`. |
| SEC-AWS-CLOUDFRONT-001 | HIGH | MEDIUM | Plain HTTP: reading the traffic needs an attacker on the network path. |
| SEC-AWS-COGNITO-001 | HIGH | MEDIUM | No MFA: account takeover still needs a stolen or guessed password. |
| SEC-AWS-DOCDB-001 | HIGH | MEDIUM | No encryption at rest: reading the disks or snapshots needs access the attacker does not have yet. |
| SEC-AWS-EBS-001 | HIGH | MEDIUM | No encryption at rest (see above). |
| SEC-AWS-ECR-001 | HIGH | MEDIUM | Scan-on-push is a hygiene control; an unscanned image is not an exposure. |
| SEC-AWS-ELASTICACHE-001 | HIGH | MEDIUM | At-rest / in-transit encryption off on a VPC-only cache: needs a foothold in the VPC. |
| SEC-AWS-ES-001 | HIGH | MEDIUM | No encryption at rest (see above). |
| SEC-AWS-ES-002 | HIGH | MEDIUM | Node-to-node traffic stays inside the domain's VPC/AWS network; reading it needs a network foothold. |
| SEC-AWS-ES-003 | HIGH | MEDIUM | Fine-grained access control is a second layer behind the domain access policy and network controls. |
| SEC-AWS-GUARDDUTY-001 | HIGH | MEDIUM | Fires on any repo with a VPC and no detector. GuardDuty is usually enabled org-wide from a delegated security account, so absence in a workload repo is not evidence it is off. Same tier as `SEC-AWS-SECURITYHUB-001`. |
| SEC-AWS-KMS-001 | HIGH | MEDIUM | Key rotation limits how long a leaked key stays useful; a hygiene control. |
| SEC-AWS-LB-LISTENER-001 | HIGH | MEDIUM | Plain HTTP: reading the traffic needs an attacker on the network path. |
| SEC-AWS-LB-LISTENER-002 | HIGH | MEDIUM | TLS < 1.2: a downgrade attack needs a network position and a weak cipher. |
| SEC-AWS-LOG-RETENTION-001 | HIGH | MEDIUM | Object Lock on the log bucket guards logs against an attacker who already has write access. |
| SEC-AWS-MSK-001 | HIGH | MEDIUM | Plaintext client-broker traffic inside the VPC: needs a network foothold. |
| SEC-AWS-NEPTUNE-001 | HIGH | MEDIUM | No encryption at rest (see above). |
| SEC-AWS-RDS-002 | HIGH | MEDIUM | No encryption at rest (see above). |
| SEC-AWS-REDSHIFT-001 | HIGH | MEDIUM | No encryption at rest (see above). |
| SEC-AWS-SNS-001 | HIGH | MEDIUM | No KMS key on a topic: messages are short-lived; reading them needs AWS-side access. |
| SEC-AWS-SQS-001 | HIGH | LOW | New queues get SQS-managed SSE by default (since Oct 2022), so a queue with neither argument is encrypted at rest. What is left is the KMS key choice. |
| SEC-AWS-VPC-FLOWLOGS-001 | HIGH | MEDIUM | Network telemetry, not the audit trail. Flow logs help an investigation; their absence does not open a path in. |
| SEC-AZURE-AKS-002 | HIGH | MEDIUM | No network policy: limits lateral movement after a pod is compromised (defence in depth). |
| SEC-AZURE-AKS-DEFENDER-001 | HIGH | MEDIUM | Per-cluster threat detection; subscription-wide Defender stays HIGH (`SEC-AZURE-DEFENDER-001`). |
| SEC-AZURE-AKS-PRIVATE-001 | HIGH | MEDIUM | Public API server still needs Entra ID / cluster credentials. The unrestricted case is `STK-AZURE-AKS-004` (HIGH). |
| SEC-AZURE-APPGW-001 | HIGH | MEDIUM | No WAF: a missing extra filter in front of the app, not an exposure on its own. |
| SEC-AZURE-APPGW-002 | HIGH | MEDIUM | Weak TLS policy: a downgrade attack needs a network position. |
| SEC-AZURE-CDN-001 | HIGH | MEDIUM | Plain HTTP: reading the traffic needs an attacker on the network path. |
| SEC-AZURE-DATABRICKS-001 | HIGH | MEDIUM | Cluster nodes get public IPs; they are still behind the workspace NSG. Hardening, not exposure. |
| SEC-AZURE-DEFENDER-001 | HIGH | MEDIUM | The absent-resource pattern fires on any repo with a resource group; Defender plans are usually set per subscription by a platform team. An explicit `tier = "Free"` still escalates to HIGH (engine-evaluated `match:`). |
| SEC-AZURE-FRONTDOOR-001 | HIGH | MEDIUM | No WAF: a missing extra filter in front of the app. |
| SEC-AZURE-FRONTDOOR-002 | HIGH | MEDIUM | TLS < 1.2: a downgrade attack needs a network position. |
| SEC-AZURE-KV-001 | HIGH | MEDIUM | Purge protection / soft delete: data loss after a mistake or compromise, not a way in. |
| SEC-AZURE-KV-002 | HIGH | MEDIUM | Every Key Vault data-plane call needs an Entra ID token; the network ACL is defence in depth. |
| SEC-AZURE-LOGGING-001 | HIGH | MEDIUM | Per-resource diagnostic logs: an investigation gap, not a way in. |
| SEC-AZURE-MONITOR-001 | HIGH | MEDIUM | Azure keeps the activity log for 90 days without a diagnostic setting; the setting adds export and longer retention. |
| SEC-AZURE-RBAC-001 | HIGH | MEDIUM | Fires on any role at subscription scope, Reader included. Over-broad scope, not a known admin grant. |
| SEC-AZURE-REDIS-001 | HIGH | MEDIUM | Non-TLS port: reading the traffic needs a network position. |
| SEC-AZURE-SQL-001 | HIGH | MEDIUM | No Entra ID admin: SQL authentication still applies; an identity-hygiene gap. |
| SEC-AZURE-SQL-ATP-001 | HIGH | MEDIUM | Per-server threat detection: a detection gap, not a way in. |
| SEC-AZURE-SQL-AUDIT-001 | HIGH | MEDIUM | Per-server auditing: an investigation gap, not a way in. |
| SEC-AZURE-SQL-VULN-001 | HIGH | MEDIUM | Vulnerability assessment is a scanning/hygiene control. |
| SEC-AZURE-STORAGE-001 | HIGH | MEDIUM | HTTP allowed: reading the traffic needs a network position (HTTPS-only is the provider default). |
| SEC-AZURE-SYNAPSE-002 | HIGH | MEDIUM | Data exfiltration protection limits what an insider or compromised identity can copy out. |
| SEC-AZURE-WEBAPP-002 | HIGH | MEDIUM | HTTPS not enforced: reading the traffic needs a network position. |
| SEC-DATASOURCE-003 | HIGH | MEDIUM | Fires on any `data "external"` / `data "http"`; it is a supply-chain risk only if the endpoint or program is compromised. Injection of user input is `SEC-DATASOURCE-002` (HIGH). |
| SEC-GCP-BUCKET-001 | HIGH | MEDIUM | A GCS bucket is public only with an `allUsers` / `allAuthenticatedUsers` grant. Missing enforcement is defence in depth (same as `SEC-AWS-S3-PUBLIC-BLOCK-001`). |
| SEC-GCP-CLOUDRUN-001 | HIGH | MEDIUM | Ingress `all` is the Cloud Run default; callers still need `roles/run.invoker` unless the service is made public. |
| SEC-GCP-CLOUDRUN-003 | HIGH | MEDIUM | Default service account is over-privileged, but abusing it needs code execution in the service first. |
| SEC-GCP-COMPUTE-PUBLIC-IP-001 | HIGH | MEDIUM | A public IP is reachable only through what the VPC firewall allows; the open firewall rule is the exposure. |
| SEC-GCP-COMPUTE-SA-001 | HIGH | MEDIUM | Default service account is over-privileged, but abusing it needs code execution on the VM first. |
| SEC-GCP-GKE-BINAUTHZ-001 | HIGH | MEDIUM | Binary Authorization is a supply-chain hardening control. |
| SEC-GCP-GKE-DBENC-001 | HIGH | MEDIUM | GKE encrypts etcd at rest by default; application-layer CMEK adds a second layer. |
| SEC-GCP-GKE-NETWORK-POLICY-001 | HIGH | MEDIUM | No network policy: limits lateral movement after a pod is compromised (defence in depth). |
| SEC-GCP-IAM-003 | HIGH | MEDIUM | Redundant project + resource grants: a least-privilege signal, not a new grant. |
| SEC-GCP-LOGGING-001 | HIGH | MEDIUM | Admin Activity audit logs are always on in GCP and cannot be turned off; the missing config is Data Access logs. |
| SEC-GCP-NETWORK-003 | HIGH | MEDIUM | Network telemetry, not the audit trail (same as `SEC-AWS-VPC-FLOWLOGS-001`). |
| SEC-GCP-REDIS-002 | HIGH | MEDIUM | Transit encryption off on a VPC-only instance: needs a network foothold. |
| SEC-GCP-SCC-001 | HIGH | MEDIUM | SCC still records findings; the missing piece is notification plumbing. |
| SEC-K8S-HELM-001 | HIGH | MEDIUM | A LoadBalancer service is often intended (ingress controllers). The exposure depends on the app and the cloud firewall. |
| SEC-K8S-HELM-003 | HIGH | MEDIUM | Supply-chain hygiene: harm needs a compromised chart repository. |
| SEC-K8S-HELM-004 | HIGH | MEDIUM | Skipping webhooks / CRDs mostly breaks apply ordering; it is not a security boundary on its own. |
| SEC-K8S-NETPOL-001 | HIGH | MEDIUM | No network policy: limits lateral movement after a pod is compromised (defence in depth). |
| SEC-K8S-NETPOL-002 | HIGH | MEDIUM | Over-permissive network policy: same defence-in-depth role as above. |
| SEC-K8S-PSA-001 | HIGH | MEDIUM | No Pod Security Admission label or pod hardening values: abusing it needs the right to create pods first. |
| SEC-PROVISIONER-001 | HIGH | MEDIUM | Fires on any `local-exec` / `remote-exec`; the commands come from the repo's own code. HashiCorp calls provisioners a last resort, not a vulnerability. |
| SEC-SENSITIVE-001 | HIGH | MEDIUM | Unmarked output prints in plan/apply logs; the value is in state either way. Reading it needs CI log access. |
| SEC-SENSITIVE-002 | HIGH | MEDIUM | Same exposure as `SEC-SENSITIVE-001` (plan/apply logs). |
| SEC-SENSITIVE-003 | HIGH | MEDIUM | Same exposure as `SEC-SENSITIVE-001` (plan/apply logs). |
| SEC-SENSITIVE-PATTERN-001 | HIGH | MEDIUM | Same exposure as `SEC-SENSITIVE-001` (plan/apply logs). |
| SEC-SUPPLY-001 | HIGH | MEDIUM | Unpinned module source: harm needs a compromised upstream. Same tier as unpinned providers (`ROB-VERSION-003`). |
| STK-AWS-EKS-001 | HIGH | MEDIUM | Fires when private endpoint access is off, not when the public endpoint is open; node-to-API traffic still uses TLS and IAM auth. |
| STK-AWS-EKS-002 | HIGH | MEDIUM | Control-plane logging: an investigation gap, not a way in. |
| STK-AWS-EKS-003 | HIGH | MEDIUM | EKS envelope-encrypts Kubernetes API data with an AWS-owned key by default (1.28+); the missing piece is a customer KMS key. |
| STK-AWS-EKS-005 | HIGH | MEDIUM | Audit log type missing: an investigation gap, not a way in. |
| STK-AWS-LAMBDA-001 | HIGH | MEDIUM | End-of-life runtime: harm needs an unpatched, reachable vulnerability. |
| STK-AWS-RDS-004 | HIGH | MEDIUM | End-of-life engine: harm needs an unpatched, reachable vulnerability. |
| STK-AZURE-AKS-003 | HIGH | MEDIUM | Without workload identity, pods use secrets or pod identity instead; a hygiene gap. |
| STK-AZURE-AKS-VERSION-001 | HIGH | MEDIUM | End-of-life Kubernetes: harm needs an unpatched, reachable vulnerability. |
| STK-AZURE-DB-001 | HIGH | MEDIUM | SSL not enforced: reading the traffic needs a network position. |
| STK-AZURE-FUNCTION-001 | HIGH | MEDIUM | End-of-life runtime: harm needs an unpatched, reachable vulnerability. |
| STK-AZURE-FUNCTION-AUTH-001 | HIGH | MEDIUM | Function-level keys (the usual HTTP trigger auth level) still guard HTTP triggers; platform auth is a second layer. |
| STK-AZURE-MYSQL-EOL-001 | HIGH | MEDIUM | End-of-life engine: harm needs an unpatched, reachable vulnerability. |
| STK-AZURE-NSG-FLOWLOG-001 | HIGH | MEDIUM | Network telemetry, not the audit trail (same as `SEC-AWS-VPC-FLOWLOGS-001`). |
| STK-AZURE-RECOVERY-001 | HIGH | MEDIUM | Soft delete: data loss after a mistake or compromise, not a way in. |
| STK-AZURE-SQL-001 | HIGH | MEDIUM | Deprecated single server: a migration and support problem, not an exposure. |
| STK-AZURE-SQL-TDE-001 | HIGH | MEDIUM | No encryption at rest (see above). |
| STK-AZURE-VM-IMG-EOL-001 | HIGH | MEDIUM | End-of-life OS image: harm needs an unpatched, reachable vulnerability. |
| STK-AZURE-WEBAPP-RUNTIME-001 | HIGH | MEDIUM | End-of-life runtime: harm needs an unpatched, reachable vulnerability. |
| STK-GCP-BIGQUERY-001 | HIGH | LOW | BigQuery encrypts every dataset at rest with Google-managed keys; CMEK is a key-ownership choice (same reasoning as `SEC-AWS-S3-001`). |
| STK-GCP-CLOUDSQL-004 | HIGH | MEDIUM | SSL not required: reading the traffic needs a network position. |
| STK-GCP-CLOUDSQL-005 | HIGH | MEDIUM | End-of-life engine: harm needs an unpatched, reachable vulnerability. |
| STK-GCP-COMPOSER-001 | HIGH | MEDIUM | Public Composer environment: the Airflow UI still needs Google sign-in and IAM. |
| STK-GCP-DNS-001 | HIGH | MEDIUM | No DNSSEC: spoofing needs a resolver cache-poisoning or network position. |
| STK-GCP-FUNCTIONS-001 | HIGH | MEDIUM | End-of-life runtime: harm needs an unpatched, reachable vulnerability. |
| STK-GCP-FUNCTIONS-002 | HIGH | MEDIUM | Default service account is over-privileged, but abusing it needs code execution in the function first. |
| STK-GCP-GCS-LOGGING-001 | HIGH | MEDIUM | Same as `SEC-GCP-BUCKET-001`: a bucket is public only with an explicit public grant. |
| STK-GCP-GKE-001 | HIGH | MEDIUM | Public node IPs are reachable only through what the VPC firewall allows. |
| STK-GCP-GKE-002 | HIGH | MEDIUM | Workload Identity off at cluster level; the pod-reads-node-token risk is `SEC-GCP-GKE-METADATA-001` (HIGH) on the node pool. |
| STK-GCP-GKE-003 | HIGH | MEDIUM | GKE encrypts etcd at rest by default; application-layer encryption adds a second layer. |
| STK-GCP-GKE-NODEPOOL-001 | HIGH | MEDIUM | Shielded nodes / secure boot guard against boot-level tampering after a foothold. |
| STK-GCP-KMS-001 | HIGH | MEDIUM | Key rotation limits how long a leaked key stays useful; a hygiene control. |
| STK-GCP-KMS-LOCATION-001 | HIGH | MEDIUM | Key ring / consumer location mismatch: a durability, cost and apply problem, not an exposure. |
| STK-GCP-LB-002 | HIGH | MEDIUM | Default SSL policy allows TLS 1.0: a downgrade attack needs a network position. |
| STK-K8S-INGRESS-001 | HIGH | MEDIUM | No TLS on the ingress: reading the traffic needs a network position (TLS is often terminated at a cloud load balancer in front). |
| STK-K8S-PSA-002 | HIGH | MEDIUM | `enforce = privileged` in one namespace: abusing it needs the right to create pods there. |
| STK-K8S-PSP-001 | HIGH | MEDIUM | A removed API (1.25+): an apply failure, not a security boundary. |
| STK-K8S-VERSION-001 | HIGH | MEDIUM | End-of-life Kubernetes: harm needs an unpatched, reachable vulnerability. |

Reviewed and kept at HIGH (34):

| Group | Rules | Why HIGH |
|---|---|---|
| Wildcard / broad IAM | SEC-AWS-IAM-001, SEC-AWS-IAM-JSON-001, SEC-AWS-IAM-POLICY-001, SEC-AWS-IAM-POLICY-003, SEC-GCP-IAM-001 | Standing decisions above; one grant reaches every resource or action. |
| World-open network / public data | SEC-AWS-SG-001, STK-AZURE-NSG-001, SEC-AZURE-SQL-002, SEC-AWS-RDS-001, SEC-GCP-SQL-PUBLIC-001, SEC-AZURE-COSMOS-001, SEC-AZURE-SYNAPSE-001, SEC-AWS-S3-PUBLIC-001, SEC-AZURE-STORAGE-002 | A data store or port reachable from the internet, or anonymous read. `SEC-AWS-SG-001` fires on any port; the engine has no per-port downgrade, so it stays HIGH (22/3389 still escalate to CRITICAL). |
| Public cluster API with no IP restriction | STK-AZURE-AKS-004, STK-GCP-GKE-004 | The control plane is open to the whole internet. |
| Disabled auth | SEC-AZURE-AKS-001, SEC-AZURE-VM-001, SEC-GCP-REDIS-001, SEC-AZURE-ACR-001 | No RBAC, SSH passwords, no Redis AUTH, a shared admin password on the registry. |
| Secrets in code, state or user data | SEC-SECRETS-ENTROPY-001, SEC-SECRETS-002, SEC-K8S-SECRET-001, SEC-AWS-ECS-001, SEC-USERDATA-001, SEC-AWS-ACCESSKEY-001, SEC-GCP-SA-KEY-001 | A credential anyone with repo, state or describe access can read. |
| Metadata credential theft | SEC-AWS-SSRF-001, STK-AWS-LAUNCH-TEMPLATE-001, SEC-GCP-GKE-METADATA-001 | One SSRF bug yields cloud credentials; industry baselines rate it high. |
| Container escape / injection | SEC-AWS-ECS-002, SEC-DATASOURCE-002 | Privileged container is host root; user input reaches a plan-time shell. |
| Audit trail | SEC-AWS-CLOUDTRAIL-002, SEC-GCP-LOG-EXCLUSION-001 | Point 3: tampering with or dropping the account audit trail. |

Judgement calls worth a second look: `SEC-GCP-SQL-PUBLIC-001` (a public
IP still needs `authorized_networks` or the IAM proxy; kept HIGH to match
`SEC-AWS-RDS-001`), the IMDS rules (an SSRF bug is a prerequisite), and
`SEC-AZURE-ACR-001`.

### Cloud defaults the sweep relies on

Checked against each provider's own documentation on 2026-10-28. If one of
these changes, revisit the rule next to it.

| Rule | Default | Source |
|---|---|---|
| SEC-AWS-SQS-001 | New queues are encrypted with SSE-SQS by default (October 2022; queues created through non-TLS endpoints excepted) | [AWS announcement](https://aws.amazon.com/about-aws/whats-new/2022/10/amazon-sqs-announces-server-side-encryption-ssq-managed-sse-sqs-default/) |
| STK-AWS-EKS-003 | EKS envelope-encrypts all Kubernetes API data with an AWS-owned KMS key on 1.28+ | [EKS user guide](https://docs.aws.amazon.com/eks/latest/userguide/envelope-encryption.html) |
| SEC-AZURE-MONITOR-001 | The activity log is kept 90 days without a diagnostic setting | [Azure Monitor activity log](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log) |
| SEC-GCP-LOGGING-001 | Admin Activity audit logs are always written and can't be disabled or excluded | [Cloud Audit Logs overview](https://docs.cloud.google.com/logging/docs/audit) |

## Standing decisions (no change, but documented)

| Rule ID                       | Urgency  | Why                                                                                            |
|-------------------------------|----------|------------------------------------------------------------------------------------------------|
| SEC-AWS-IAM-POLICY-005        | CRITICAL | `actions=["*"]` AND `resources=["*"]` = canonical AdministratorAccess shape; one statement, full account compromise. |
| SEC-AWS-IAM-POLICY-004        | CRITICAL | `principals.identifiers=["*"]` makes whatever resource the policy attaches to public.          |
| SEC-AWS-IAM-POLICY-002        | CRITICAL | `iam:*` action grants self-mutating IAM (privesc class).                                       |
| SEC-AWS-IAM-POLICY-001        | HIGH     | `actions=["*"]` alone is bad but scoped to `resources` set. Promote when paired with -005.     |
| SEC-AWS-IAM-POLICY-003        | HIGH     | Symmetric: `resources=["*"]` alone is bad but scoped to `actions` set.                          |
| ROB-VERSION-002               | LOW      | Hygiene — submodule version pinning. Doesn't change runtime behaviour.                         |

## Calibration cadence

Spot-check 5 rules per major round; full sweep every 3 rounds. Track
positive/negative fixture pass rates per urgency tier to detect rules
that are mis-tiered (e.g. CRITICAL with high false-positive rate).
