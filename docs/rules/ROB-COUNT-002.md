# ℹ️ ROB-COUNT-002 — Module mixes count-based and for_each-based resources

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Module mixes count-based and for_each-based resources.** This rule has `default_urgency: LOW` and operates on a module blast radius. 

## What this checks

1. **`count_foreach_mix`** — _a `count_foreach_mix` pattern._
  Same module directory uses both count and for_each on different resources — forces consumers to learn both splat and dynamic reference forms

## Why it likely fired

Same module directory uses both count and for_each on different resources — forces consumers to learn both splat and dynamic reference forms

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-COUNT-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Pick one iteration form per module. `for_each` is almost always the right
answer (stable keys, better error messages, cleaner module output shape).
Migrate `count`-based resources to `for_each = toset(...)` so consumers
don't have to remember which form each output uses.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
# Unify all iteration to for_each; use moved{} to avoid destroy+create
resource "aws_instance" "web" {
  for_each      = toset(var.names)
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"
}

moved {
  from = aws_instance.web[0]
  to   = aws_instance.web["primary"]
}
```

## Verification

After the refactor, `terraform plan` diff should be zero for the
unchanged resources (use `moved {}` blocks to teach Terraform that
`aws_instance.web[0]` is now `aws_instance.web["primary"]`).

## References

**Source**
  - [`catalog/ROB-COUNT-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-COUNT-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-COUNT-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-COUNT-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-COUNT-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
