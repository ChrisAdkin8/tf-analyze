# ℹ️ ROB-UNUSED-002 — Declared output is never consumed by any caller

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Declared output is never consumed by any caller.** This rule has `default_urgency: LOW` and operates on a module blast radius. 

## What this checks

1. **`output_unused`** — _a `output_unused` pattern._
  output declared in a child module but never referenced as module.X.output_name by any caller in the repo

## Why it likely fired

output declared in a child module but never referenced as module.X.output_name by any caller in the repo

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-UNUSED-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Remove the unused output if no external consumer (CI scripts, other repos)
depends on it. Unused outputs clutter `terraform output` and may expose
sensitive values unnecessarily.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
# Remove the unused output declaration entirely
# Before (delete this block):
# output "legacy_endpoint" {
#   value = aws_instance.app.public_ip
# }

# After: output is gone; verify no external CI scripts reference it
```

## Verification

Run `terraform validate` after removing the output. Search for any
external references (CI scripts, other repos) before deleting.

## References

**Source**
  - [`catalog/ROB-UNUSED-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-UNUSED-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-UNUSED-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-UNUSED-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-UNUSED-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
