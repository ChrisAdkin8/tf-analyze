# 💡 STK-DEPRECATION-002 — Deprecated data source: data.template_file

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Deprecated data source: data.template_file.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`deprecated_datasource`** — _a `deprecated_datasource` pattern._
  data.template_file has been deprecated since Terraform 0.12 in favour of templatefile()

## Why it likely fired

data.template_file has been deprecated since Terraform 0.12 in favour of templatefile()

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-DEPRECATION-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace with the built-in `templatefile()` function:

```hcl
# Before
data "template_file" "init" {
  template = file("${path.module}/init.tpl")
  vars     = { name = var.name }
}

# After
locals {
  init = templatefile("${path.module}/init.tpl", { name = var.name })
}
```

`templatefile()` is evaluated at plan time natively — no provider
dependency, no resource graph node, and error messages point at the real
source line instead of a synthetic data-source.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
locals {
  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    environment = var.environment
  })
}
```

## Verification

Run `terraform plan` and confirm the rendered value is identical
(`diff <(terraform console <<< 'data.template_file.init.rendered')
<(terraform console <<< 'local.init')`).

## References

**Source**
  - [`catalog/STK-DEPRECATION-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-DEPRECATION-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-DEPRECATION-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-DEPRECATION-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-DEPRECATION-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
