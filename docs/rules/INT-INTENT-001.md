# 💡 INT-INTENT-001 — Security-intent variable defaults to false/null/0

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Security-intent variable defaults to false/null/0.** This rule has `default_urgency: MEDIUM` and operates on a module blast radius. 

## What this checks

1. **`intent_gap`** — _the variable-name suggests one intent but the resource configuration contradicts it._
  >

## Why it likely fired

>

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain INT-INTENT-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `default = true` or remove the default and require explicit
assignment. Add a `validation` block to prevent callers from passing
false when the intent is to enforce the control.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
variable "enable_encryption" {
  type        = bool
  description = "Encrypt data at rest (must be true in production)"
  default     = true

  validation {
    condition     = var.enable_encryption == true
    error_message = "enable_encryption must be true — encryption cannot be disabled"
  }
}
```

## Verification

Confirm the variable has `default = true` or no default, and a
`validation` block enforces the constraint.

## References

**Source**
  - [`catalog/INT-INTENT-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/INT-INTENT-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain INT-INTENT-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore INT-INTENT-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - INT-INTENT-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
