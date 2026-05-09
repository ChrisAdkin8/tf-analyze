# 💡 SEC-PROVIDER-001 — Provider version constraint missing upper bound

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **Provider version constraint missing upper bound.** This rule has `default_urgency: MEDIUM` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`grep`** matching `/(?<![_a-zA-Z])version\s*=\s*">=\s*[0-9]/` — _a textual regex matched somewhere in the file._
2. **`grep`** matching `/required_providers\s*\{[^}]*(?<![_a-zA-Z])version\s*=\s*">=\s*[0-9]/` — _a textual regex matched somewhere in the file._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-PROVIDER-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace `>= X.Y` constraints with `~> X.Y` to bound the major version.
For production stability, prefer `~> X.Y` (minor pin) over `~> X` (major
pin). The 2026-04-11 finding history shows 70% of provider-related plan
failures came from automatic major version upgrades.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0, < 6.0"
    }
  }
}
```

## Verification

After updating the constraint, run `terraform init -upgrade` and confirm
the locked provider version in `.terraform.lock.hcl` is within the new
range.

## References

**Source**
  - [`catalog/SEC-PROVIDER-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-PROVIDER-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-PROVIDER-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-PROVIDER-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-PROVIDER-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
