# 🚨 SEC-GCP-IAM-002 — Public IAM binding (allUsers / allAuthenticatedUsers)

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **Public IAM binding (allUsers / allAuthenticatedUsers).** This rule has `default_urgency: CRITICAL` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`resource_arg`** on `google_storage_bucket_iam_member` (`member`) matching `/^(allUsers|allAuthenticatedUsers)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
2. **`resource_arg`** on `google_project_iam_member` (`member`) matching `/^(allUsers|allAuthenticatedUsers)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
3. **`resource_arg`** on `google_bigquery_dataset_iam_member` (`member`) matching `/^(allUsers|allAuthenticatedUsers)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-IAM-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Public IAM grants must be removed unless the resource is intentionally
a public website or public dataset. If public access is intentional,
document it in CLAUDE.md and add a `# tf-analyze:ignore SEC-IAM-002`
comment on the binding line.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_storage_bucket_iam_member" "example" {
  bucket = google_storage_bucket.example.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.example.email}"
}
```

## Verification

After applying the fix, attempt to access the resource without
credentials and confirm the request is denied. Re-run tf-analyze in
mode:verify-fixed.

## References

**CIS Benchmark**
  - `CIS 5.1`
  - `CIS 7.1`

**PCI-DSS**
  - `Req-6.4`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**Source**
  - [`catalog/SEC-GCP-IAM-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-IAM-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-IAM-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-IAM-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-IAM-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
