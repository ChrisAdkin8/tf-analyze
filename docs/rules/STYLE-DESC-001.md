# ℹ️ STYLE-DESC-001 — Variable or output missing description

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: style](https://img.shields.io/badge/section-style-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Variable or output missing description.** This rule has `default_urgency: LOW` and operates on a module blast radius. 

## What this checks

1. **`variable_missing_description`** — _a `variable_missing_description` pattern._
  variable block without a description argument
2. **`output_missing_description`** — _a `output_missing_description` pattern._
  output block without a description argument

## Why it likely fired

variable block without a description argument

output block without a description argument

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STYLE-DESC-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a `description` argument to every variable and output. Descriptions
populate `terraform-docs` output, IDE tooltips, and the Terraform
registry module page. Without them, consumers must read the source to
understand what a variable controls or an output provides.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
variable "environment" {
  type        = string
  description = "Deployment environment: dev, staging, or prod"
}

output "instance_id" {
  description = "EC2 instance ID of the application server"
  value       = aws_instance.app.id
}
```

## Verification

Run `grep -rn 'variable\|output' *.tf` and confirm each block has a
`description` line. Or run `terraform-docs markdown .` and check for
blank description columns.

## References

**Source**
  - [`catalog/STYLE-DESC-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STYLE-DESC-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STYLE-DESC-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STYLE-DESC-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STYLE-DESC-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
