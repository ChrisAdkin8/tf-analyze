# 💡 ROB-VERSION-001 — required_version floor too old for skill assumptions

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **required_version floor too old for skill assumptions.** This rule has `default_urgency: MEDIUM` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`grep`** matching `/required_version\s*=\s*"[~>=\s]*0\./` — _a textual regex matched somewhere in the file._
2. **`grep`** matching `/required_version\s*=\s*"[~>=\s]*1\.[0-5]/` — _a textual regex matched somewhere in the file._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-VERSION-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `required_version = "~> 1.10"` (or whatever the current Terraform
major is). Many checks in this skill assume features only available in
Terraform 1.6+: native test framework (`*.tftest.hcl`), `import` blocks,
`optional()` in object types, `moved` blocks, conditional outputs.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
terraform {
  required_version = ">= 1.5.0, < 2.0.0"
}
```

## Verification

Run `terraform version` and confirm it satisfies the new constraint.
CI should pin the same version via `setup-terraform`.

## References

**Source**
  - [`catalog/ROB-VERSION-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-VERSION-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-VERSION-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-VERSION-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-VERSION-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
