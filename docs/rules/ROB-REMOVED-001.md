# ℹ️ ROB-REMOVED-001 — Stale removed block may need cleanup

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Stale removed block may need cleanup.** This rule has `default_urgency: LOW` and operates on a module blast radius. 

## What this checks

1. **`removed_block_present`** — _a `removed { ... }` block exists with a stale target._
  Terraform 1.7+ `removed` block detected — verify the destroy/forget has
been applied and the block can be removed.

## Why it likely fired

Terraform 1.7+ `removed` block detected — verify the destroy/forget has
been applied and the block can be removed.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-REMOVED-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Once `terraform apply` has executed the `removed` block (destroying or
forgetting the resource), delete the block to keep the configuration
clean. Stale `removed` blocks accumulate noise the same way stale `moved`
blocks do, and they are a warning sign that a refactor was started but
never finished.

If the intent was to *forget* the resource (keep it in the cloud, drop
it from state), confirm `lifecycle { destroy = false }` was set. If the
intent was to *destroy*, the default `destroy = true` is correct.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
# Remove the removed block after terraform apply has executed it:
# Delete the block below once the resource has been destroyed/forgotten.
#
# removed {
#   from = aws_instance.legacy
#   lifecycle { destroy = false }
# }
```

## Verification

Run `terraform plan` — if the plan shows no changes related to the
removed address, the block is safe to delete. After deletion, re-run
`terraform plan` to confirm still-no-changes.

## References

**Related rules**
  - [`ROB-MOVED-001`](./ROB-MOVED-001.md)

**Source**
  - [`catalog/ROB-REMOVED-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-REMOVED-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-REMOVED-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-REMOVED-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-REMOVED-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
