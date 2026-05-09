# ⚠️ STK-GCP-CLOUDSQL-003 — Cloud SQL instance missing deletion protection

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Cloud SQL instance missing deletion protection.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_sql_database_instance` (`deletion_protection`) — _the resource is missing a required attribute (or nested attribute path)._
2. **`hcl_attr`** on `google_sql_database_instance` (`deletion_protection`) not equal to `True` — _an attribute value differs from the expected literal._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-CLOUDSQL-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `deletion_protection = true` on every Cloud SQL instance. This is
the only safety net against `terraform destroy` removing a database
with all of its data.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_sql_database_instance" "example" {
  name             = "example"
  database_version = "POSTGRES_15"
  deletion_protection = true
  settings {
    tier = "db-f1-micro"
  }
}
```

## Verification

```sh
`gcloud sql instances describe <name> --format='value(settings.deletionProtectionEnabled)'`
must return `True`.
```

## References

**CIS Benchmark**
  - `CIS 6.6`

**Source**
  - [`catalog/STK-GCP-CLOUDSQL-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-CLOUDSQL-003.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-CLOUDSQL-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-CLOUDSQL-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-CLOUDSQL-003
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
