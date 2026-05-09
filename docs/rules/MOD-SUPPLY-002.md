# ℹ️ MOD-SUPPLY-002 — Module uses raw git source instead of registry

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: module](https://img.shields.io/badge/section-module-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Module uses raw git source instead of registry.** This rule has `default_urgency: LOW` and operates on a module blast radius. 

## What this checks

1. **`grep`** matching `/source\s*=\s*"git::/` — _a textual regex matched somewhere in the file._
  Module sourced from raw git URL rather than Terraform Registry

## Why it likely fired

Module sourced from raw git URL rather than Terraform Registry

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain MOD-SUPPLY-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Prefer Terraform Registry sources (`namespace/module/provider`) over raw
git URLs. Registry modules are integrity-hashed in `.terraform.lock.hcl`;
raw git sources bypass the digest check.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
# Before: module sourced from raw git
# source = "git::https://github.com/example/terraform-aws-vpc.git"

# After: registry source with version pin
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
}
```

## Verification

Replace `git::` sources with registry equivalents where available.

## References

**SOC 2 Trust Services Criteria**
  - `CC9.2`

**MITRE ATT&CK**
  - [`T1195.002`](https://attack.mitre.org/techniques/T1195/002/)

**Source**
  - [`catalog/MOD-SUPPLY-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/MOD-SUPPLY-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain MOD-SUPPLY-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore MOD-SUPPLY-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - MOD-SUPPLY-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
