# ⚠️ STK-GCP-GCS-LOGGING-001 — GCS bucket logging target lacks public_access_prevention

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **GCS bucket logging target lacks public_access_prevention.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`graph_check`** — _a corpus-wide graph check fired (cross-resource invariant)._
  A `google_storage_bucket` references another bucket via
`logging.log_bucket = google_storage_bucket.<x>.name`, but that
target bucket does not set `public_access_prevention = "enforced"`.
Logging targets accumulate access records for every read/write on
the source bucket; if the target is publicly readable, an attacker
can enumerate which objects exist and how often they're read.

## Why it likely fired

A `google_storage_bucket` references another bucket via
`logging.log_bucket = google_storage_bucket.<x>.name`, but that
target bucket does not set `public_access_prevention = "enforced"`.
Logging targets accumulate access records for every read/write on
the source bucket; if the target is publicly readable, an attacker
can enumerate which objects exist and how often they're read.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-GCS-LOGGING-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add `public_access_prevention = "enforced"` to the target bucket
block. Also confirm `uniform_bucket_level_access = true` and that no
IAM binding grants `allUsers` or `allAuthenticatedUsers` access. If
the source and target bucket have different blast-radius requirements
(e.g., source is internal, target is shared with auditors), document
the rationale in a comment near the `logging` block so the next
reviewer doesn't downgrade it.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_storage_bucket" "logs" {
  name                        = "example-logs"
  location                    = "US"
  public_access_prevention    = "enforced"
  uniform_bucket_level_access = true
  lifecycle_rule {
    condition { age = 90 }
    action { type = "Delete" }
  }
}
```

## Verification

After applying the fix, run:

    gcloud storage buckets describe gs://<target> --format='value(publicAccessPrevention)'

and confirm it prints `enforced`. Re-run tf-analyze; STK-GCS-LOGGING-001
should not fire.

## References

**CIS Benchmark**
  - `CIS 5.1`

**Related rules**
  - [`SEC-BUCKET-001`](./SEC-BUCKET-001.md)
  - [`SEC-BUCKET-002`](./SEC-BUCKET-002.md)

**Source**
  - [`catalog/STK-GCP-GCS-LOGGING-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-GCS-LOGGING-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-GCS-LOGGING-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-GCS-LOGGING-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-GCS-LOGGING-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
