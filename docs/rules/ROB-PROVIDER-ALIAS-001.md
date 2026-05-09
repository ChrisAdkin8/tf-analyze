# ⚠️ ROB-PROVIDER-ALIAS-001 — Module references provider alias that is not declared

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Module references provider alias that is not declared.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`provider_alias_module_mismatch`** — _a `provider_alias_module_mismatch` pattern._
  module providers={} maps to pname.alias that is not declared in the calling config

## Why it likely fired

module providers={} maps to pname.alias that is not declared in the calling config

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-PROVIDER-ALIAS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

The child module expects a provider alias that the root config does not
declare — at apply time Terraform will fall back to the default provider,
which may target the wrong project/region/account. Declare the alias
explicitly:

```hcl
provider "google" {
  alias   = "eu"
  project = var.project_id
  region  = "europe-west1"
}

module "eu_stack" {
  source    = "./modules/stack"
  providers = { google = google.eu }
}
```

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
provider "aws" {
  alias  = "eu_west"
  region = "eu-west-1"
}

module "eu_stack" {
  source    = "./modules/stack"
  providers = { aws = aws.eu_west }
}
```

## Verification

```sh
`terraform validate` succeeds, and `terraform plan` shows resources landing
in the intended region/account.
```

## References

**Source**
  - [`catalog/ROB-PROVIDER-ALIAS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-PROVIDER-ALIAS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-PROVIDER-ALIAS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-PROVIDER-ALIAS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-PROVIDER-ALIAS-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
