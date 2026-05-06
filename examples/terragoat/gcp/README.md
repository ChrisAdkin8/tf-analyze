# GCP — OWASP Top 10 corpus

10 deliberately vulnerable Terraform files, one per OWASP 2021 Top 10 category, mapped to GCP-specific anti-patterns. Each file is self-contained, self-documenting, and triggers a known set of `tf-analyze` findings. Together they exercise ~27 catalogue rules.

## File layout

| File | OWASP | What's vulnerable |
|---|---|---|
| [`01_broken_access_control.tf`](01_broken_access_control.tf) | A01 | `roles/owner` at project; `allUsers` on a bucket; same SA at project + resource scope |
| [`02_cryptographic_failures.tf`](02_cryptographic_failures.tf) | A02 | KMS key with no `rotation_period`; bucket↔key-ring location mismatch; sensitive output unmarked; Cloud Memorystore Redis with auth disabled and TLS disabled |
| [`03_injection.tf`](03_injection.tf) | A03 | `null_resource` provisioner shelling out to a tfvar; `data.external` with user-controlled query |
| [`04_insecure_design.tf`](04_insecure_design.tf) | A04 | One SA used by every workload; stateful Spanner + state bucket without `prevent_destroy` |
| [`05_security_misconfiguration.tf`](05_security_misconfiguration.tf) | A05 | Default Compute SA; public-IP `access_config`; world-open SSH; world-open RDP; GCP firewall exposing PostgreSQL port (5432) to 0.0.0.0/0; Cloud SQL with `ipv4_enabled = true`; Cloud SQL without `deletion_protection`; Cloud SQL without `require_ssl`; bucket missing `public_access_prevention` and UBLA; Artifact Registry repository without CMEK |
| [`06_vulnerable_components.tf`](06_vulnerable_components.tf) | A06 | Module without `version`; Cloud SQL pinned to `POSTGRES_9_6` (EOL, triggers STK-GCP-CLOUDSQL-004 + STK-GCP-CLOUDSQL-005) |
| [`07_identification_auth.tf`](07_identification_auth.tf) | A07 | GKE missing Workload Identity, network_policy, node-pool secure-boot, and master authorized networks; static service account key created in Terraform |
| [`08_data_integrity.tf`](08_data_integrity.tf) | A08 | Bucket without versioning; BigQuery dataset without CMEK; stale `moved` and `removed` blocks |
| [`09_logging_monitoring.tf`](09_logging_monitoring.tf) | A09 | No `google_project_iam_audit_config`; logging-target bucket lacks `public_access_prevention`; VPC subnet without flow logs; DNS zone without DNSSEC |
| [`10_ssrf.tf`](10_ssrf.tf) | A10 | Cloud SQL public IPv4; Cloud Run with `INGRESS_TRAFFIC_ALL` (SEC-GCP-CLOUDRUN-001) |
| [`versions.tf`](versions.tf) | — | Pins `required_version >= 1.10.0` so `SEC-EPHEMERAL-001` is in scope; `~> 5.40` google provider |

## Expected findings

Running `python3 ../../../scripts/detect.py --target . --format json | jq -r '.findings[].id' | sort | uniq -c` from this directory produces a known distribution. The exact rule IDs you should see at least once each:

```
SEC-GCP-IAM-001, SEC-GCP-IAM-002, SEC-GCP-IAM-003,
SEC-GCP-BUCKET-001, SEC-GCP-BUCKET-002,
SEC-GCP-COMPUTE-SA-001, SEC-GCP-COMPUTE-PUBLIC-IP-001, SEC-GCP-COMPUTE-SHIELDED-001,
SEC-GCP-NETWORK-001, SEC-GCP-NETWORK-002, SEC-GCP-NETWORK-003, SEC-GCP-NETWORK-004,
SEC-GCP-REDIS-001, SEC-GCP-REDIS-002,
SEC-GCP-SQL-PUBLIC-001, SEC-GCP-CLOUDRUN-001,
SEC-GCP-LOGGING-001, SEC-GCP-SA-KEY-001, SEC-SENSITIVE-001,
SEC-PROVISIONER-001, SEC-DATASOURCE-001,
SEC-GCP-GKE-NETWORK-POLICY-001,
STK-GCP-ARTIFACT-001,
STK-GCP-BUCKET-001, STK-GCP-GCS-LOGGING-001,
STK-GCP-GKE-001, STK-GCP-GKE-002, STK-GCP-GKE-003, STK-GCP-GKE-004, STK-GCP-GKE-NODEPOOL-001,
STK-GCP-KMS-001, STK-GCP-KMS-LOCATION-001,
STK-GCP-CLOUDSQL-001, STK-GCP-CLOUDSQL-003, STK-GCP-CLOUDSQL-004, STK-GCP-CLOUDSQL-005,
STK-GCP-BIGQUERY-001, STK-GCP-DNS-001, STK-GCP-PUBSUB-001,
ROB-MOVED-001, ROB-REMOVED-001,
MOD-PIN-001, OPS-ENV-001
```

Plus the corpus-level rules (`CI-TEST-001`, `OPS-GCP-LABELS-001`, `STYLE-DESC-001`, `ROB-GCP-LIFECYCLE-001`, `ROB-VERSION-001`, `COST-GCP-RISK-001`) that fire as a function of the corpus shape rather than any specific anti-pattern. Total finding count: **80**.

## OWASP → GCP control mapping

The OWASP 2021 categories are originally web-application-shaped. The mapping to IaC misconfigurations isn't always obvious; this section explains the bridge.

### A01 — Broken Access Control

In the web context: an authenticated user reaches a resource that should require additional authorization. In GCP IaC: an IAM principal is bound at a scope wider than the workload requires, or to a resource role that grants more verbs than necessary. The three patterns here capture the most common shapes — broad role at project scope, public membership, and the silent over-privilege pattern where a project-level binding makes a narrower resource-level one redundant.

### A02 — Cryptographic Failures

GCP encrypts everything at rest by default with Google-managed keys. "Cryptographic failure" almost always means **CMEK is misconfigured** — not absent. Three of the most consequential CMEK mistakes: no rotation, region mismatch, and sensitive value escape via outputs.

### A03 — Injection

Terraform-time injection is a small but real attack surface. The vector isn't HCL itself — HCL is data — it's the shell-out points: `null_resource` with `local-exec`, `data.external`, `null_resource` with `remote-exec`. Anywhere a tfvar lands in a `bash -c` argument unsanitised. Recommendation: keep these out of Terraform entirely. If unavoidable, validate inputs in a `validation` block on the variable.

### A04 — Insecure Design

The hardest category to demonstrate cleanly because it's about absence of layered controls, not a single anti-pattern. The example here picks the most common Terraform shape: a single shared SA across every workload, which converts a single pod compromise into a project-wide compromise. Pair with `lifecycle { prevent_destroy = true }` on stateful resources — together these aren't separate rules, they're a defense-in-depth pattern.

### A05 — Security Misconfiguration

The largest category by line count. The defaults in question are mostly per-resource toggles: SAs, public IPs, firewall rules, public-IP CloudSQL, bucket public-access-prevention, UBLA. tfsec, Checkov, and KICS each flag tens of millions of these per year against real-world Terraform on GitHub.

### A06 — Vulnerable and Outdated Components

In Terraform, "outdated component" maps to four shapes: unpinned modules, unpinned providers, unset `required_version`, and cloud-managed runtimes pinned to EOL versions (`POSTGRES_9_6`, `nodejs10`, `python3.7`, etc.). The corpus demonstrates the first and the last.

### A07 — Identification and Authentication Failures

For GCP, the consequential auth failure is the pod-to-cloud boundary on GKE. Without Workload Identity, a pod's only way to authenticate to GCS / BigQuery / KMS is a service-account JSON key mounted as a Kubernetes Secret — a long-lived credential that survives every pod restart, ships in every etcd backup, and is hard to rotate. Pair with shielded VMs (secure boot + integrity monitoring) for the node-trust half of the question.

### A08 — Software and Data Integrity Failures

Three Terraform-shaped integrity failures: object versioning off (so an accidental destroy is unrecoverable), stale `moved` blocks (refactor was applied months ago, the block is dead history), stale `removed` blocks (TF 1.7 declarative destroy left behind after the cloud resource is gone).

### A09 — Security Logging and Monitoring Failures

Cloud Audit Logs configuration at the project level (`google_project_iam_audit_config`) is the baseline that lets you reconstruct an incident. Without it, post-incident investigation has no forensic timeline. The graph-style finding `STK-GCP-GCS-LOGGING-001` adds a layer: the log-sink target itself must be hardened, otherwise the logs are exfiltrable even when the source bucket isn't.

### A10 — Server-Side Request Forgery

In an IaC context, SSRF maps to network configurations that let an in-cluster workload reach destinations the operator didn't intend — most famously the Capital One 2019 incident where SSRF on a WAF host fetched the EC2 metadata service token (S3-broad). On GCP the analogues are: VPC Service Controls absent on sensitive APIs, Cloud SQL with `ipv4_enabled = true` reachable from any VPC, Cloud Run with `INGRESS_TRAFFIC_ALL`. Full SSRF coverage requires VPC SC + metadata-service hardening that aren't yet first-class catalogue rules; this file primarily documents the category.

## Running it

```sh
# From this directory:
python3 ../../../scripts/detect.py --target . --format text

# Just the IDs:
python3 ../../../scripts/detect.py --target . --format json \
  | python3 -c '
import json, sys
from collections import Counter
fs = json.load(sys.stdin)["findings"]
for k, v in sorted(Counter(f["id"] for f in fs).items()):
    print(f"{v:>3} {k}")
print(f"---\n{len(fs)} total")
'

# SARIF for IDE / CI:
python3 ../../../scripts/detect.py --target . --format sarif > gcp-terragoat.sarif
```

## Adding to the corpus

When you add a new GCP rule to the catalogue:

1. Identify which OWASP category it falls under (consult the table above).
2. Add a triggering snippet to the relevant `0N_*.tf` file.
3. Update the `Expected tf-analyze findings` block in that file's header comment.
4. Update the rule list in this README.
5. Re-run the scan — the new ID should appear in the count.

Stay within OWASP categories — the discipline of "this rule fits A0N because…" forces you to think about *why* the rule matters, not just *what* it detects, which improves recommendation quality on real findings.
