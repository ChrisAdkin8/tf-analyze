# ⚠️ ROB-COUNTREF-002 — Unguarded indexed reference to count = length(...) resource

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Unguarded indexed reference to count = length(...) resource.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`count_length_unguarded`** — _a `count_length_unguarded` pattern._
  Resource created with count = length(var.x), and another resource references [N] without length/try guard — off-by-one on removal

## Why it likely fired

Resource created with count = length(var.x), and another resource references [N] without length/try guard — off-by-one on removal

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-COUNTREF-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

`count = length(var.x)` makes the resource keyed by position. Any
reference like `aws_instance.web[2].id` breaks when an earlier element is
removed, because the third slot no longer exists.

Prefer `for_each = toset(var.x)` (or a map) so references are name-keyed,
or guard index references with `length(aws_instance.web) > 2 ? aws_instance.web[2].id : null`.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
# Prefer for_each with name-keyed instances (stable across removals)
resource "aws_instance" "web" {
  for_each      = toset(var.names)
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"
}

output "first_ip" {
  value = try(values(aws_instance.web)[0].public_ip, null)
}
```

## Verification

Remove an element from `var.x`, run `terraform plan`, confirm Terraform
does not produce spurious destroy/create plans for unrelated elements.

## References

**Source**
  - [`catalog/ROB-COUNTREF-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-COUNTREF-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-COUNTREF-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-COUNTREF-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-COUNTREF-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
