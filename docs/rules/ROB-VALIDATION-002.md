# 💡 ROB-VALIDATION-002 — Variable typed as bare any

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Variable typed as bare any.** This rule has `default_urgency: MEDIUM` and operates on a module blast radius. 

## What this checks

1. **`variable_type`** — _a `variable_type` pattern._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-VALIDATION-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace `type = any` with a concrete type. Use `string`, `number`, `bool`,
`list(string)`, `map(string)`, or `object({...})`. The `any` type defers
type checking until plan and produces opaque downstream errors.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
variable "environment" {
  type        = string
  description = "Deployment environment name"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging, or prod"
  }
}

variable "tags" {
  type        = map(string)
  description = "Resource tags"
  default     = {}
}
```

## Verification

Run `terraform validate` and confirm no warning. Pass a deliberately
wrong-typed value via `-var` and confirm Terraform rejects it at parse
time.

## References

**Source**
  - [`catalog/ROB-VALIDATION-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-VALIDATION-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-VALIDATION-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-VALIDATION-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-VALIDATION-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
