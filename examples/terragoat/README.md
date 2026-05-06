# `examples/terragoat/` — deliberately vulnerable Terraform corpus

A multi-cloud, OWASP-Top-10-organised corpus of intentionally insecure Terraform. It serves three jobs:

1. **Smoke test for the `tf-analyze` engine.** Running `python3 scripts/detect.py --target examples/terragoat` produces **274 findings** across 30 files. Drift in this count is a regression signal — the CI workflow gates on it.
2. **Calibration target for new rules.** When you write a new detector, drop a triggering snippet into the cloud + OWASP slot it belongs in. Re-run the corpus scan; your new rule ID appears alongside the existing ones with no spurious cross-talk.
3. **Live demo for first-time users.** Reports against the corpus are realistic-shaped (multi-cloud, multi-resource, OWASP-narrative-aware) rather than the isolated single-rule fixtures under `fixtures/`.

> **Naming.** "Terragoat" follows the convention popularised by Bridgecrew's [`terragoat`](https://github.com/bridgecrewio/terragoat) — an intentionally vulnerable IaC corpus used to exercise scanners. This corpus is independently authored, organised by OWASP Top 10 (2021) categories, and tailored to the rules `tf-analyze` ships today.

## Layout

```
examples/terragoat/
├── README.md          (this file — overview and how-to-run)
├── aws/               (10 OWASP-mapped .tf files + versions.tf)
├── gcp/               (10 OWASP-mapped .tf files + versions.tf)
└── azure/             (10 OWASP-mapped .tf files + versions.tf)
```

Each cloud folder contains exactly **10 numbered files**, one per OWASP 2021 Top 10 category:

| File | OWASP 2021 |
|---|---|
| `01_broken_access_control.tf` | A01 — Broken Access Control |
| `02_cryptographic_failures.tf` | A02 — Cryptographic Failures |
| `03_injection.tf` | A03 — Injection |
| `04_insecure_design.tf` | A04 — Insecure Design |
| `05_security_misconfiguration.tf` | A05 — Security Misconfiguration |
| `06_vulnerable_components.tf` | A06 — Vulnerable and Outdated Components |
| `07_identification_auth.tf` | A07 — Identification and Authentication Failures |
| `08_data_integrity.tf` | A08 — Software and Data Integrity Failures |
| `09_logging_monitoring.tf` | A09 — Security Logging and Monitoring Failures |
| `10_ssrf.tf` | A10 — Server-Side Request Forgery |

Each file:
- Has a header comment with the OWASP category, the cloud, the vulnerability description, real-world impact, expected `tf-analyze` finding IDs, and a one-line fix summary.
- Is self-contained where practical (some Azure files share the demo resource group declared in `versions.tf`).
- Does **not** need to apply cleanly with `terraform apply` — it's a static-analysis corpus, not a deployable module.

## Coverage by cloud

| Cloud | Unique rule IDs exercised | Findings | Notes |
|---|---|---|---|
| **GCP** | 48 | 79 | Densest per-file coverage — the catalogue is GCP-first. Includes SA key creation (A07), DB port firewall exposure (A05), Redis auth/TLS (A02), and Artifact Registry CMEK (A05). |
| **AWS** | 44 | 98 | Full coverage of EKS (incl. partial log-type detection), RDS/Aurora, EC2, S3 (incl. access logging), CloudTrail, KMS, SQS/SNS, ECR, GuardDuty, launch template IMDSv2, CloudFront, Cognito, API Gateway, Lambda, ECS. |
| **Azure** | 30 | 83 | Full coverage of AKS, Key Vault, Storage, SQL, App Service, RBAC, NSG, ACR, Azure Monitor, and Linux VM password authentication. |
| **Corpus-level** | 14 | 14 | `resource_absent` rules that fire once per scan: GuardDuty, ECR lifecycle, VPC flow logs, S3 public-access block, S3 access logging, EKS IRSA, Route53 DNSSEC, Azure Monitor, Azure SQL AAD, NSG flow logs, SQL TDE, GCP Audit Logs, Secrets Manager rotation. |
| **Total** | **127 unique IDs** | **274** | Drift > ±5 should be investigated. The canonical count is `python3 scripts/detect.py --target examples/terragoat --format json \| python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d["findings"]))'`. |

## Per-file finding counts

| File | Findings |
|---|---|
| `aws/01_broken_access_control.tf` | 7 |
| `aws/02_cryptographic_failures.tf` | 21 |
| `aws/03_injection.tf` | 3 |
| `aws/04_insecure_design.tf` | 4 |
| `aws/05_security_misconfiguration.tf` | 16 |
| `aws/06_vulnerable_components.tf` | 12 |
| `aws/07_identification_auth.tf` | 2 |
| `aws/08_data_integrity.tf` | 12 |
| `aws/09_logging_monitoring.tf` | 14 |
| `aws/10_ssrf.tf` | 4 |
| `aws/versions.tf` | 3 |
| `azure/01_broken_access_control.tf` | 7 |
| `azure/02_cryptographic_failures.tf` | 10 |
| `azure/03_injection.tf` | 2 |
| `azure/04_insecure_design.tf` | 3 |
| `azure/05_security_misconfiguration.tf` | 18 |
| `azure/06_vulnerable_components.tf` | 17 |
| `azure/07_identification_auth.tf` | 10 |
| `azure/08_data_integrity.tf` | 6 |
| `azure/09_logging_monitoring.tf` | 2 |
| `azure/10_ssrf.tf` | 6 |
| `azure/versions.tf` | 2 |
| `gcp/01_broken_access_control.tf` | 4 |
| `gcp/02_cryptographic_failures.tf` | 9 |
| `gcp/03_injection.tf` | 3 |
| `gcp/04_insecure_design.tf` | 3 |
| `gcp/05_security_misconfiguration.tf` | 24 |
| `gcp/06_vulnerable_components.tf` | 7 |
| `gcp/07_identification_auth.tf` | 9 |
| `gcp/08_data_integrity.tf` | 6 |
| `gcp/09_logging_monitoring.tf` | 7 |
| `gcp/10_ssrf.tf` | 6 |
| `gcp/versions.tf` | 1 |
| corpus-level (`resource_absent` rules) | 14 |

## Running the corpus

```sh
# Whole corpus — should print 274
python3 scripts/detect.py --target examples/terragoat --format json \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d["findings"]))'

# Full text report
python3 scripts/detect.py --target examples/terragoat

# Per cloud
python3 scripts/detect.py --target examples/terragoat/gcp
python3 scripts/detect.py --target examples/terragoat/aws
python3 scripts/detect.py --target examples/terragoat/azure

# Write report to file instead of stdout
python3 scripts/detect.py --target examples/terragoat --output /tmp/terragoat-report.md

# SARIF for IDE / CI integration
python3 scripts/detect.py --target examples/terragoat --format sarif > terragoat.sarif

# HTML for sharing with non-CLI reviewers
python3 scripts/detect.py --target examples/terragoat --format html > terragoat.html
```

## Why split by cloud and OWASP category?

**Why per cloud:** AWS / GCP / Azure have non-overlapping resource types and IAM models. Mixing them in one file produces unrealistic Terraform that no real-world repo would resemble — and the per-resource detection rules need to see realistic-shaped HCL. Keeping each cloud in its own folder also lets reviewers focus on the cloud they actually run.

**Why per OWASP category:** OWASP categories are the universal vocabulary security reviewers know. A finding labelled "A05:2021 Security Misconfiguration" needs no further translation; "the GCS bucket is missing public_access_prevention" does. The OWASP framing also forces discipline when adding new rules — *why does this matter, in the language a security architect uses?* — which improves recommendation quality.

The two axes (cloud × OWASP) compose: 3 clouds × 10 categories = 30 files. Plus a `versions.tf` per cloud. This is enough to demonstrate every catalogue rule that exists today.

## Why both `fixtures/` and this corpus?

- **`fixtures/`** are minimal one-rule-per-directory inputs used by `self_test.py`. A failing self-test pinpoints exactly which rule broke. Each fixture is one resource, sometimes two.
- **`examples/terragoat/`** is a representative *project* that exercises rules in combination — including `graph_check` rules that need ≥2 resources to fire, corpus-level `resource_absent` rules that need a directory rather than a file, and the OWASP narrative that frames "why does this matter".

Isolated fixtures alone miss interaction bugs. A project-shaped corpus alone loses diagnostic precision. Both serve.

## Adding to the corpus

When you add a new rule to the catalogue:

1. Identify the cloud (GCP/AWS/Azure) and the OWASP category.
2. Add a triggering snippet to the relevant `<cloud>/0N_*.tf` file.
3. Update the file's header comment under `Expected tf-analyze findings`.
4. Re-run `python3 scripts/detect.py --target examples/terragoat --format json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["findings"]))'` and confirm the count increased.
5. Update the per-file finding count table in this README.
6. Bump the canonical count in `README.md` at the repo root.

If a rule applies cross-cloud (cloud-neutral, like `ROB-MOVED-001`), put the trigger in the GCP folder by default — it has the densest existing coverage, so per-cloud accounting stays simple.

For corpus-level `resource_absent` rules, no per-file trigger is needed — the rule fires once per scan when the required resource type is absent from the target directory.
