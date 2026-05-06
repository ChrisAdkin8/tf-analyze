# AWS — OWASP Top 10 corpus

10 deliberately vulnerable Terraform files demonstrating OWASP 2021 categories on AWS.

## File layout

| File | OWASP | What's vulnerable |
|---|---|---|
| [`01_broken_access_control.tf`](01_broken_access_control.tf) | A01 | IAM policy with `Action:*, Resource:*`; bucket without public-access block; role assumed by `Principal: "*"` |
| [`02_cryptographic_failures.tf`](02_cryptographic_failures.tf) | A02 | S3 without SSE; RDS `storage_encrypted = false`; EBS without `encrypted`; KMS key without `enable_key_rotation` |
| [`03_injection.tf`](03_injection.tf) | A03 | EC2 `user_data` constructed from unvalidated tfvar; `null_resource` shelling out with interpolated input |
| [`04_insecure_design.tf`](04_insecure_design.tf) | A04 | Hardcoded API key in HCL; one shared Lambda role with `AdministratorAccess`; DynamoDB without `prevent_destroy` |
| [`05_security_misconfiguration.tf`](05_security_misconfiguration.tf) | A05 | Security group `0.0.0.0/0` on tcp:22; EC2 with `associate_public_ip_address = true`; RDS `publicly_accessible = true` |
| [`06_vulnerable_components.tf`](06_vulnerable_components.tf) | A06 | Lambda on EOL `nodejs10.x`; hardcoded AMI; module without `version` |
| [`07_identification_auth.tf`](07_identification_auth.tf) | A07 | Long-lived IAM user with access key; inline `*/*` policy; weak `aws_iam_account_password_policy` |
| [`08_data_integrity.tf`](08_data_integrity.tf) | A08 | S3 without versioning; RDS `backup_retention_period = 0`; ECR without image scanning |
| [`09_logging_monitoring.tf`](09_logging_monitoring.tf) | A09 | CloudTrail single-region, no log-file validation; VPC without flow logs; S3 without access logging |
| [`10_ssrf.tf`](10_ssrf.tf) | A10 | EC2 without `metadata_options.http_tokens = "required"` (IMDSv1) — the Capital One shape |
| [`versions.tf`](versions.tf) | — | Pins `~> 5.50` aws provider, `>= 1.10.0` Terraform |

## Expected findings

92 findings across 42 unique rule IDs. From inside this directory:

```sh
python3 ../../../scripts/detect.py --target . --format json \
  | python3 -c '
import json, sys
from collections import Counter
fs = json.load(sys.stdin)["findings"]
for k, v in sorted(Counter(f["id"] for f in fs).items()):
    print(f"{v:>3} {k}")
print(f"---\n{len(fs)} total")
'
```

You should see at least one instance of each of:

| Domain | Rule IDs |
|---|---|
| SEC | `SEC-AWS-ACCESSKEY-001`, `SEC-AWS-CLOUDTRAIL-001/002`, `SEC-AWS-EBS-001`, `SEC-AWS-ECR-001/002`, `SEC-AWS-GUARDDUTY-001`, `SEC-AWS-IAM-001/002`, `SEC-AWS-KMS-001`, `SEC-AWS-RDS-001/002`, `SEC-AWS-S3-001`, `SEC-AWS-S3-PUBLIC-BLOCK-001`, `SEC-AWS-SG-001`, `SEC-AWS-SNS-001`, `SEC-AWS-SQS-001`, `SEC-AWS-SSRF-001`, `SEC-AWS-VPC-FLOWLOGS-001`, `SEC-PROVISIONER-001`, `SEC-SECRETS-001` |
| ROB | `ROB-AWS-BACKEND-001`, `ROB-AWS-LIFECYCLE-001/002`, `ROB-AWS-RDS-001/002/003`, `ROB-AWS-S3-001`, `ROB-VERSION-001/003` |
| STK | `STK-AWS-EKS-001/002/003/004`, `STK-AWS-LAMBDA-001`, `STK-AWS-LAUNCH-TEMPLATE-001`, `STK-AWS-RDS-004`, `STK-AWS-ROUTE53-001` |
| OPS/COST/MOD | `OPS-AWS-TAGS-001`, `COST-AWS-RISK-001`, `MOD-PIN-001`, `CI-TEST-001` |

`SEC-AWS-ECR-002`, `SEC-AWS-GUARDDUTY-001`, `SEC-AWS-S3-PUBLIC-BLOCK-001`, `SEC-AWS-VPC-FLOWLOGS-001`, `STK-AWS-EKS-004`, `STK-AWS-ROUTE53-001` are corpus-level `resource_absent` rules — they fire once per scan of this directory, not per file.

## OWASP → AWS control mapping

### A01 — Broken Access Control

The single largest source of AWS data leaks. The corpus demonstrates three shapes: the IAM wildcard policy (`SEC-AWS-IAM-001`), the missing public-access block on S3 (`SEC-AWS-S3-PUBLIC-BLOCK-001`), and the wildcard `Principal` in an assume-role policy (`SEC-AWS-IAM-002`).

### A02 — Cryptographic Failures

AWS encrypts everything at rest by default *if you ask*. The corpus demonstrates four explicit opt-outs: S3 without SSE, RDS without `storage_encrypted`, EBS without `encrypted`, KMS without rotation. Each is a one-line opt-in that's missed surprisingly often.

### A03 — Injection

EC2 `user_data` is the AWS-specific injection vector — whatever the operator put into the tfvar runs as root at first boot. The provisioner anti-pattern is identical across clouds.

### A04 — Insecure Design

Three Terraform-shaped design failures: hardcoded credentials (Step 0a credential pattern detection in `tf-analyze` flags the `sk-live-` prefix; check the report), shared IAM role across all Lambdas (one Lambda compromise = full access), and missing `prevent_destroy` on DynamoDB.

### A05 — Security Misconfiguration

The most-flagged category by every IaC scanner. AWS-specific shapes: SGs with `0.0.0.0/0` ingress, EC2 with public IPs, RDS publicly accessible. tfsec flags ~30 rules under this umbrella; the corpus exercises three of the most consequential.

### A06 — Vulnerable and Outdated Components

Lambda runtimes on the AWS deprecation calendar (`STK-AWS-LAMBDA-001`) and launch templates without IMDSv2 enforcement (`STK-AWS-LAUNCH-TEMPLATE-001`). The corpus also exercises unpinned module sources (`MOD-PIN-001`) and a `required_providers` entry without a version constraint (`ROB-VERSION-003`).

### A07 — Identification and Authentication Failures

Long-lived IAM access keys are the AWS analogue of GCP's static service-account JSON keys. Replacing them with IAM Identity Center (formerly SSO) + role assumption is the standard mitigation. The weak password policy is a separate but related shape — even with SSO, the account password policy applies to root.

### A08 — Software and Data Integrity Failures

S3 versioning, RDS backups, and ECR image scanning. Each is a one-line on-toggle that's free; not setting them is policy decay over time as new buckets and databases get added without inheriting the team standard.

### A09 — Security Logging and Monitoring Failures

CloudTrail multi-region + log-file validation is the foundation of every AWS post-incident investigation. Without it, "what happened in us-west-2 between 2am and 4am" has no answer.

### A10 — Server-Side Request Forgery

The Capital One 2019 incident is the canonical case study. Three IaC-shaped controls together prevent it: IMDSv2-only via `metadata_options.http_tokens = "required"`, narrow per-workload IAM roles, and VPC endpoints for AWS services.

## Running it

```sh
# From this directory:
python3 ../../../scripts/detect.py --target . --format text

# Or for SARIF / HTML / JSON, see the parent terragoat/README.md.
```

## Adding to this corpus

When you add a new AWS rule to the catalogue:

1. Identify the OWASP category from the table above.
2. Add a triggering snippet to the relevant `0N_*.tf` file.
3. Update the file's header comment under `Expected tf-analyze findings`.
4. Re-run the scan to confirm the new ID appears in the count.

Use `python3 scripts/detect.py --new-rule SEC-AWS-NEWRULE-001` to scaffold the catalogue YAML + fixture skeleton.
