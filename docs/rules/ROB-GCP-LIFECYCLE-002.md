# ⚠️ ROB-GCP-LIFECYCLE-002 — Stateful resource has force_destroy=true

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Stateful resource has force_destroy=true.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `google_storage_bucket` (`force_destroy`) matching `/^true$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
2. **`resource_arg`** on `google_project` (`force_destroy`) matching `/^true$/` — _the resource declares the named attribute, but its value matches the rule's pattern._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-GCP-LIFECYCLE-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `force_destroy = false` (or remove the argument). With force_destroy
enabled, a `terraform destroy` will silently delete every object in the
bucket without asking, even if those objects were uploaded by an
application long after the bucket was created.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_storage_bucket" "example" {
  name          = "example"
  location      = "US"
  force_destroy = false
}
```

## Verification

Run `terraform plan` and confirm no diff. Manually upload an object
and run `terraform destroy` — it should fail with "bucket is not empty".

## References

**Source**
  - [`catalog/ROB-GCP-LIFECYCLE-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-GCP-LIFECYCLE-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-GCP-LIFECYCLE-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-GCP-LIFECYCLE-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-GCP-LIFECYCLE-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
