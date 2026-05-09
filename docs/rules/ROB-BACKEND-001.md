# 💡 ROB-BACKEND-001 — Inconsistent backend configuration across root modules

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **Inconsistent backend configuration across root modules.** This rule has `default_urgency: MEDIUM` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`backend_inconsistency`** — _a `backend_inconsistency` pattern._
  multiple terraform backend blocks with different types or missing key attributes

## Why it likely fired

multiple terraform backend blocks with different types or missing key attributes

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-BACKEND-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Ensure all root modules in the repo use the same backend type and
consistent naming patterns for bucket/key/prefix. Mixed backends
(e.g., one module using S3, another using GCS) make state management
and disaster recovery harder.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
# Standardise on S3 backend across all root modules
terraform {
  backend "s3" {
    bucket         = "myorg-terraform-state"
    key            = "envs/prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}
```

## Verification

Grep for all `backend` blocks and compare their configurations.

## References

**Source**
  - [`catalog/ROB-BACKEND-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-BACKEND-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-BACKEND-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-BACKEND-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-BACKEND-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
