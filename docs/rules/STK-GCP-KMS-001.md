# ⚠️ STK-GCP-KMS-001 — KMS crypto key missing rotation period

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **KMS crypto key missing rotation period.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_kms_crypto_key` (`rotation_period`) — _the resource is missing a required attribute (or nested attribute path)._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-KMS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `rotation_period = "7776000s"` (90 days, the CIS maximum) or
shorter on every symmetric encryption key:

    resource "google_kms_crypto_key" "data" {
      name     = "data"
      key_ring = google_kms_key_ring.primary.id
      purpose  = "ENCRYPT_DECRYPT"

      rotation_period = "7776000s"  # 90 days

      lifecycle {
        prevent_destroy = true
      }
    }

Asymmetric keys (purpose = `ASYMMETRIC_SIGN` /
`ASYMMETRIC_DECRYPT`) cannot rotate without invalidating
signatures and are exempt — suppress the finding via inline
`# tf-analyze:ignore STK-KMS-001` and a one-line reason.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_kms_crypto_key" "example" {
  name            = "example"
  key_ring        = google_kms_key_ring.example.id
  rotation_period = "7776000s"
  lifecycle {
    prevent_destroy = true
  }
}
```

## Verification

After applying:

    gcloud kms keys describe <key> --keyring <ring> --location <loc> \\
      --format='value(rotationPeriod)'

Must return a value ≤ `7776000s`.

## References

**CIS Benchmark**
  - `CIS 1.10`

**Related rules**
  - [`STK-KMS-LOCATION-001`](./STK-KMS-LOCATION-001.md)

**Source**
  - [`catalog/STK-GCP-KMS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-KMS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-KMS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-KMS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-KMS-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
