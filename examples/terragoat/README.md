# `examples/terragoat/` — deliberately vulnerable Terraform

A small, multi-file Terraform project where every block is wrong on
purpose. It serves three jobs:

1. **Smoke test** for `tf-analyze` after a refactor — `python3 scripts/detect.py --target examples/terragoat` should produce a known set of findings (table below). Drift in the count is a regression signal.
2. **Demo for new users** — show what the report looks like on a real-shaped (multi-file, GCP + Azure + Vault) corpus rather than a single isolated fixture.
3. **Calibration target** — when you write a new rule, drop a triggering snippet into the relevant file here and confirm the rule fires alongside the others without spurious cross-talk.

> **Naming.** "Terragoat" follows the convention popularised by Bridgecrew's [`terragoat`](https://github.com/bridgecrewio/terragoat) — an intentionally vulnerable IaC corpus used to exercise scanners. This is a much smaller GCP/Azure-focused variant tailored to `tf-analyze`'s rule set.

## Files and what they exercise

| File | Rules triggered | What's wrong |
|---|---|---|
| [`versions.tf`](versions.tf) | (sets up TF 1.10+ required_version so SEC-EPHEMERAL-001 applies) | — |
| [`iam.tf`](iam.tf) | `SEC-IAM-001`, `SEC-IAM-002`, `SEC-IAM-003`, `SEC-AZURE-RBAC-001` | Project-level `roles/owner`; `allUsers` on a bucket; member at both project and resource scope; Azure role assignment at subscription scope |
| [`storage.tf`](storage.tf) | `SEC-BUCKET-001`, `SEC-BUCKET-002`, `STK-BUCKET-001`, `OPS-ENV-001`, `ROB-LIFECYCLE-001`, `STK-GCS-LOGGING-001` | Bucket missing `public_access_prevention`, `uniform_bucket_level_access`, versioning; prod-labelled with no protection; logging target itself unprotected |
| [`compute.tf`](compute.tf) | `SEC-COMPUTE-SA-001`, `SEC-COMPUTE-PUBLIC-IP-001`, `SEC-NETWORK-001` | VM uses default SA; VM has public IP; firewall rule allows 0.0.0.0/0 → tcp:22 |
| [`gke.tf`](gke.tf) | `STK-GKE-002`, `SEC-GKE-NETWORK-POLICY-001`, `STK-GKE-NODEPOOL-001` | Cluster missing Workload Identity, `network_policy`, and node pool secure-boot/integrity-monitoring |
| [`sql.tf`](sql.tf) | `SEC-SQL-PUBLIC-001` | Cloud SQL with `ipv4_enabled = true` |
| [`kms.tf`](kms.tf) | `STK-KMS-001`, `STK-KMS-LOCATION-001` | Symmetric key with no `rotation_period`; bucket in `us-central1` referencing key ring in `us-east1` |
| [`secrets.tf`](secrets.tf) | `SEC-EPHEMERAL-001`, `SEC-SENSITIVE-001` | `data "vault_kv_secret_v2"` instead of `ephemeral` (TF 1.10+); output exposes sensitive var without `sensitive = true` |
| [`checks.tf`](checks.tf) | `ROB-CHECK-001`, `ROB-PRECONDITION-001`, `ROB-MOVED-001`, `ROB-REMOVED-001` | Empty `check` block; precondition without `error_message`; stale `moved` and `removed` blocks |

Plus the corpus-level rules that always fire on a fixture project: `CI-TEST-001` (no `*.tftest.hcl`), `SEC-LOGGING-001` (no audit log config), and likely `OPS-LABELS-001`, `STYLE-DESC-001` for the variables that lack descriptions.

## How to run it

```sh
# Full report
python3 ../../scripts/detect.py --target . --format text

# Just the IDs and counts
python3 ../../scripts/detect.py --target . --format json | \
  python3 -c '
import json, sys
from collections import Counter
data = json.load(sys.stdin)
c = Counter(f["id"] for f in data["findings"])
for k, v in c.most_common():
    print(f"{v:>3} {k}")
'

# SARIF for opening in any IDE that consumes it
python3 ../../scripts/detect.py --target . --format sarif > terragoat.sarif

# HTML for sharing with non-CLI users
python3 ../../scripts/detect.py --target . --format html > terragoat.html
```

## Verifying the corpus after a rule change

When you add or modify a rule, run:

```sh
python3 ../../scripts/detect.py --target . --format json | \
  jq -r '.findings[].id' | sort -u
```

Compare against the expected ID set in the table above. If you've **added** a rule:

1. Drop a triggering snippet into the most-relevant `.tf` file (or add a new one).
2. Update the table above.
3. Re-run the command — your new ID should appear in the diff.

If you've **broken** a rule, an existing ID will disappear from the output. Either fix the rule or update the corpus to keep the trigger active.

## Why include a corpus when fixtures already exist?

`fixtures/` are minimal one-rule-at-a-time inputs used by `self_test.py` — they isolate the rule under test so a passing self-test pinpoints exactly which rule is broken. The terragoat corpus is the opposite: a representative *project* that exercises rules in combination, including cross-resource (graph) checks that need ≥2 resources to fire and corpus-level checks (`CI-TEST-001`, `SEC-LOGGING-001`) that need a directory rather than a single file.

If you only have isolated fixtures, you'll miss bugs that show up under interaction (e.g. two rules suppressing each other, or a corpus-level scan with the wrong file glob). If you only have a project-shaped corpus, you can't tell which rule fired the finding and self-test loses its diagnostic precision. Both serve.
