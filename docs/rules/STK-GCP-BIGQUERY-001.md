# ⚠️ STK-GCP-BIGQUERY-001 — BigQuery dataset missing default CMEK

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **BigQuery dataset missing default CMEK.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_bigquery_dataset` (`default_encryption_configuration.kms_key_name`) — _the resource is missing a required attribute (or nested attribute path)._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-BIGQUERY-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add `default_encryption_configuration { kms_key_name = <kms-key> }`
on every dataset. Without this, new tables fall back to Google-managed
keys and CIS GCP 7.2/7.3 are not satisfied.

    resource "google_bigquery_dataset" "analytics" {
      dataset_id = "analytics"
      location   = "US"

      default_encryption_configuration {
        kms_key_name = google_kms_crypto_key.bq.id
      }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "google_bigquery_dataset" "example" {
  dataset_id = "example"
  location   = "US"
  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.bq.id
  }
}
```

## Verification

```sh
`bq show --format=prettyjson <dataset> | jq '.defaultEncryptionConfiguration'`
must return a key reference, not `null`.
```

## References

**CIS Benchmark**
  - `CIS 7.3`

**Source**
  - [`catalog/STK-GCP-BIGQUERY-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-BIGQUERY-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-BIGQUERY-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-BIGQUERY-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-BIGQUERY-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
