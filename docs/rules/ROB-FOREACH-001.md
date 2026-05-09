# 💡 ROB-FOREACH-001 — for_each over list instead of map/set

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **for_each over list instead of map/set.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`foreach_over_list`** — _a `foreach_over_list` pattern._
  for_each iterates over a list/tuple literal (not toset/map) — order-based keys, destructive on reorder

## Why it likely fired

for_each iterates over a list/tuple literal (not toset/map) — order-based keys, destructive on reorder

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-FOREACH-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

`for_each` must iterate over a `map` or a `set`. Passing a list silently
works only because Terraform errors late — and when elements are removed
or reordered, instances are destroyed and recreated because their keys are
position-dependent.

```hcl
for_each = toset(var.names)         # set (stable keys)
# or
for_each = { for n in var.names : n => {} }   # map with stable keys
```

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
# Before: for_each = ["alice", "bob"]  — list, order-sensitive
# After: wrap in toset() for stable keys
resource "aws_iam_user" "team" {
  for_each = toset(var.usernames)
  name     = each.key
}
```

## Verification

Run `terraform plan` after the change — if stable keys were already in use,
diff should be zero.

## References

**Source**
  - [`catalog/ROB-FOREACH-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-FOREACH-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-FOREACH-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-FOREACH-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-FOREACH-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
