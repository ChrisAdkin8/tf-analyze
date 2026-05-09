# 💡 ROB-COUNTREF-001 — Unguarded reference to count-conditional resource

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Unguarded reference to count-conditional resource.** This rule has `default_urgency: MEDIUM` and operates on a module blast radius. 

## What this checks

1. **`count_index_ref`** — _a `count_index_ref` pattern._
  reference to resource[0] or module.X.output[0] where the source uses count and the consumer file has no matching conditional guard

## Why it likely fired

reference to resource[0] or module.X.output[0] where the source uses count and the consumer file has no matching conditional guard

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-COUNTREF-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Guard indexed references to count-conditional resources with a
conditional expression or a try() wrapper:

```hcl
# Instead of:
value = aws_instance.optional[0].id

# Use:
value = length(aws_instance.optional) > 0 ? aws_instance.optional[0].id : null
# Or:
value = try(aws_instance.optional[0].id, null)
```

Without the guard, destroying the conditional resource (count = 0)
produces an "index out of range" error.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
output "instance_id" {
  value = try(aws_instance.optional[0].id, null)
}

# Or with explicit length guard
output "instance_ip" {
  value = length(aws_instance.optional) > 0 ? aws_instance.optional[0].public_ip : null
}
```

## Verification

Set the count condition to false and run `terraform plan`. The plan
should succeed without index errors.

## References

**Source**
  - [`catalog/ROB-COUNTREF-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-COUNTREF-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-COUNTREF-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-COUNTREF-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-COUNTREF-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
