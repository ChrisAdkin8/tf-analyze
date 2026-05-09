# ℹ️ ROB-MOVED-001 — Stale moved block may need cleanup

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Stale moved block may need cleanup.** This rule has `default_urgency: LOW` and operates on a module blast radius. 

## What this checks

1. **`moved_block_present`** — _a `moved { ... }` block points at a target that no longer exists._
  moved block detected — verify it has been applied and can be removed

## Why it likely fired

moved block detected — verify it has been applied and can be removed

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-MOVED-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

After `terraform apply` has successfully run with this `moved` block and
the state reflects the new address, remove the block to keep the config
clean. Stale moved blocks accumulate noise and can confuse future readers.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
# Remove the moved block after terraform apply has reconciled state:
# Delete the block below — it is no longer needed once state is updated.
#
# moved {
#   from = aws_instance.old
#   to   = aws_instance.new
# }
```

## Verification

Run `terraform plan` — if the plan shows no changes related to the moved
resource, the block is safe to remove.

## References

**Source**
  - [`catalog/ROB-MOVED-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-MOVED-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-MOVED-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-MOVED-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-MOVED-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
