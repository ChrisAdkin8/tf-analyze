# 💡 STK-GCP-BUCKET-001 — GCS bucket missing versioning

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **GCS bucket missing versioning.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_storage_bucket` (`versioning.enabled`) — _the resource is missing a required attribute (or nested attribute path)._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-BUCKET-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add object versioning so accidental overwrites and deletes are
recoverable:

    resource "google_storage_bucket" "data" {
      # ...
      versioning {
        enabled = true
      }
      lifecycle_rule {
        condition  { num_newer_versions = 10 }
        action     { type = "Delete" }
      }
    }

Pair versioning with a `lifecycle_rule` (above) to expire
non-current versions, otherwise storage costs grow unbounded for
high-write buckets. State buckets (`*-tfstate`) and any bucket
storing audit logs MUST have versioning on — losing prior state
during a botched apply is unrecoverable otherwise.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_storage_bucket" "example" {
  name     = "example"
  location = "US"
  versioning {
    enabled = true
  }
}
```

## Verification

After applying:

    gcloud storage buckets describe gs://<name> \\
      --format='value(versioning.enabled)'

Must return `True`. Re-run tf-analyze; STK-BUCKET-001 should not fire.

## References

**CIS Benchmark**
  - `CIS 5.3`

**Related rules**
  - [`SEC-BUCKET-001`](./SEC-BUCKET-001.md)
  - [`STK-GCS-LOGGING-001`](./STK-GCS-LOGGING-001.md)

**Source**
  - [`catalog/STK-GCP-BUCKET-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-BUCKET-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-BUCKET-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-BUCKET-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-BUCKET-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
