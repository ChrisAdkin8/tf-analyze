# 💡 ROB-VALIDATION-001 — Variable accepts dangerous input without validation block

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Variable accepts dangerous input without validation block.** This rule has `default_urgency: MEDIUM` and operates on a module blast radius. 

## What this checks

1. **`variable_missing_validation`** — _a `variable_missing_validation` pattern._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-VALIDATION-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a `validation { condition = ... error_message = ... }` block. For
region/location use a regex that matches the cloud provider's region
format (e.g., `^[a-z]+-[a-z]+[0-9]+$` for GCP). For cron, validate the
5-field shape. For environment, restrict to `["dev", "staging", "prod"]`.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
variable "environment" {
  type        = string
  description = "Deployment environment"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod"
  }
}
```

## Verification

Run `terraform plan -var=<name>=<bad-value>` and confirm Terraform
rejects the input with the validation error message.

## References

**Source**
  - [`catalog/ROB-VALIDATION-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-VALIDATION-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-VALIDATION-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-VALIDATION-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-VALIDATION-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
