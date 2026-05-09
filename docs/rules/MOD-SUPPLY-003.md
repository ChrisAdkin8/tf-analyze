# ⚠️ MOD-SUPPLY-003 — Registry module missing version constraint

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: module](https://img.shields.io/badge/section-module-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Registry module missing version constraint.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`grep`** matching `/source\s*=\s*"[a-zA-Z][a-zA-Z0-9_-]*/[a-zA-Z][a-zA-Z0-9_-]*/[a-zA-Z][a-zA-Z0-9_-]*"/` — _a textual regex matched somewhere in the file._
  Module block without a version = "..." argument

## Why it likely fired

Module block without a version = "..." argument

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain MOD-SUPPLY-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add `version = "~> X.Y"` to every registry module block. Without a
version constraint, `terraform init` resolves the latest available
version making builds non-reproducible.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
module "example" {
  source  = "hashicorp/consul/aws"
  version = ">= 0.11.0, < 0.12.0"
}
```

## Verification

Confirm every module block referencing a registry source has a `version`
argument.

## References

**SOC 2 Trust Services Criteria**
  - `CC9.2`

**MITRE ATT&CK**
  - [`T1195.002`](https://attack.mitre.org/techniques/T1195/002/)

**Source**
  - [`catalog/MOD-SUPPLY-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/MOD-SUPPLY-003.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain MOD-SUPPLY-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore MOD-SUPPLY-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - MOD-SUPPLY-003
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
