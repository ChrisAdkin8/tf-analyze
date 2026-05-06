# AWS — OWASP Top 10 corpus

10 deliberately vulnerable Terraform files demonstrating OWASP 2021 categories on AWS. AWS-specific catalogue coverage in `tf-analyze` is intentionally narrower than GCP — the corpus is part-demo, part-roadmap for catalogue expansion.

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

The AWS catalogue has grown significantly. Active rules now include: `SEC-AWS-IAM-001/002`, `SEC-AWS-S3-001`, `SEC-AWS-SG-001`, `SEC-AWS-SSRF-001`, `SEC-AWS-EBS-001`, `SEC-AWS-RDS-001/002`, `SEC-AWS-KMS-001`, `SEC-AWS-CLOUDTRAIL-001`, `SEC-AWS-ACCESSKEY-001`, `SEC-AWS-VPC-FLOWLOGS-001`, `SEC-AWS-ECR-001`, `SEC-SECRETS-001`, `ROB-AWS-LIFECYCLE-001`, `ROB-AWS-RDS-001/002`, `ROB-AWS-S3-001`, `STK-AWS-LAMBDA-001`. From inside this directory:

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

You should see: `SEC-AWS-IAM-001`, `SEC-AWS-IAM-002`, `SEC-AWS-S3-001`, `SEC-AWS-SG-001`, `SEC-AWS-SSRF-001`, `SEC-AWS-VPC-FLOWLOGS-001`, `SEC-AWS-ECR-001`, `SEC-SECRETS-001`, `ROB-AWS-LIFECYCLE-001`, `ROB-AWS-RDS-001`, `SEC-PROVISIONER-001`, `MOD-PIN-001`, plus corpus-level rules (`CI-TEST-001`, `STYLE-DESC-001`, etc.).

## OWASP → AWS control mapping

### A01 — Broken Access Control

The single largest source of AWS data leaks. Bridgecrew/Checkov has ~15 AWS rules under this umbrella; `tf-analyze` has one (`SEC-AWS-IAM-001`). The corpus demonstrates three shapes: the IAM wildcard policy, the missing public-access block on S3, and the wildcard `Principal` in an assume-role policy. All three are catalogue expansion targets.

### A02 — Cryptographic Failures

AWS encrypts everything at rest by default *if you ask*. The corpus demonstrates four explicit opt-outs: S3 without SSE, RDS without `storage_encrypted`, EBS without `encrypted`, KMS without rotation. Each is a one-line opt-in that's missed surprisingly often.

### A03 — Injection

EC2 `user_data` is the AWS-specific injection vector — whatever the operator put into the tfvar runs as root at first boot. The provisioner anti-pattern is identical across clouds.

### A04 — Insecure Design

Three Terraform-shaped design failures: hardcoded credentials (Step 0a credential pattern detection in `tf-analyze` flags the `sk-live-` prefix; check the report), shared IAM role across all Lambdas (one Lambda compromise = full access), and missing `prevent_destroy` on DynamoDB.

### A05 — Security Misconfiguration

The most-flagged category by every IaC scanner. AWS-specific shapes: SGs with `0.0.0.0/0` ingress, EC2 with public IPs, RDS publicly accessible. tfsec flags ~30 rules under this umbrella; the corpus exercises three of the most consequential.

### A06 — Vulnerable and Outdated Components

Lambda runtimes on the AWS deprecation calendar are the most consequential AWS-specific shape — once deprecated, the function silently stops receiving security patches. `nodejs10.x`, `python3.6`, `dotnetcore2.1`, and earlier are all in the catalogue's future scope.

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

## Catalogue expansion roadmap

If you're contributing AWS rules to `tf-analyze`, this corpus is the starting point. Each file's header lists "Expected tf-analyze findings" — anything not yet flagged is a candidate for a new catalogue entry. Suggested first additions, ranked:

1. `SEC-AWS-IMDS-001` — EC2 without IMDSv2-required (10_ssrf.tf trigger).
2. `SEC-AWS-S3-PUBLIC-BLOCK-001` — bucket without `aws_s3_bucket_public_access_block` (01_broken_access_control.tf).
3. `SEC-AWS-RDS-ENCRYPT-001` — RDS without `storage_encrypted = true` (02_cryptographic_failures.tf).
4. `SEC-AWS-RDS-PUBLIC-001` — RDS with `publicly_accessible = true` (05_security_misconfiguration.tf).
5. `SEC-AWS-LAMBDA-RUNTIME-001` — Lambda on EOL runtime (06_vulnerable_components.tf).
6. `SEC-AWS-CLOUDTRAIL-001` — CloudTrail not multi-region or no log-file validation (09_logging_monitoring.tf).

Use `python3 scripts/detect.py --new-rule SEC-AWS-IMDS-001` to scaffold each one. The corresponding fixture goes in `fixtures/aws_imds_v1/main.tf` and the trigger in this corpus's `10_ssrf.tf` should already match.
