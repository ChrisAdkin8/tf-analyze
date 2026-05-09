# 💡 INT-INTENT-002 — Variable description says 'must be true' but has no validation block

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Variable description says 'must be true' but has no validation block.** This rule has `default_urgency: MEDIUM` and operates on a module blast radius. 

## What this checks

1. **`intent_gap`** — _the variable-name suggests one intent but the resource configuration contradicts it._
  >

## Why it likely fired

>

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain INT-INTENT-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a `validation` block:
  validation {
    condition     = var.X == true
    error_message = "X must be true."
  }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
variable "require_mfa" {
  type        = bool
  description = "MFA must be enabled for all users"

  validation {
    condition     = var.require_mfa == true
    error_message = "require_mfa must be true — MFA cannot be disabled"
  }
}
```

## Verification

Run `terraform validate` with a violating tfvars and confirm the
validation error fires.

## References

**Source**
  - [`catalog/INT-INTENT-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/INT-INTENT-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain INT-INTENT-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore INT-INTENT-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - INT-INTENT-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
