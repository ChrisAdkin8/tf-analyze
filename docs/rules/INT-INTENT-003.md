# ⚠️ INT-INTENT-003 — Prod-tagged resource has deletion_protection=false

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Prod-tagged resource has deletion_protection=false.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`intent_gap`** — _the variable-name suggests one intent but the resource configuration contradicts it._
  >

## Why it likely fired

>

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain INT-INTENT-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `deletion_protection = true` on all prod-tagged resources, or
remove the prod tag if this is genuinely a non-production resource.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_db_instance" "example" {
  deletion_protection = true
  tags = {
    Environment = "production"
  }
}
```

_Enabling deletion_protection on an existing resource is an in-place modification; no replacement is triggered._

## Verification

Confirm no prod-tagged resource carries `deletion_protection = false`.

## References

**Source**
  - [`catalog/INT-INTENT-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/INT-INTENT-003.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain INT-INTENT-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore INT-INTENT-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - INT-INTENT-003
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
