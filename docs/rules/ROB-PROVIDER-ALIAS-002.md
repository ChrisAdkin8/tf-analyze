# ℹ️ ROB-PROVIDER-ALIAS-002 — Provider alias declared but never referenced

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Provider alias declared but never referenced.** This rule has `default_urgency: LOW` and operates on a module blast radius. 

## What this checks

1. **`provider_alias_unused`** — _a `provider_alias_unused` pattern._
  provider block declares alias but no resource/module references it

## Why it likely fired

provider block declares alias but no resource/module references it

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-PROVIDER-ALIAS-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Remove the unused alias, or wire it to the resources/modules that should
use it via `provider = google.<alias>` or module-level `providers = { … }`.
Unused aliases hide intent and cause confusion when readers look for where
a specific region/account is actually used.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
# Option A — remove the unused alias entirely
# provider "aws" { alias = "eu_west" ... }  <-- delete this block

# Option B — wire it to the modules that need it
module "eu_app" {
  source    = "./modules/app"
  providers = { aws = aws.eu_west }
}
```

## Verification

Run `terraform plan` and confirm the resource graph is unchanged. If you
removed the alias, callers that relied on the default provider still work.

## References

**Source**
  - [`catalog/ROB-PROVIDER-ALIAS-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-PROVIDER-ALIAS-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-PROVIDER-ALIAS-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-PROVIDER-ALIAS-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-PROVIDER-ALIAS-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
