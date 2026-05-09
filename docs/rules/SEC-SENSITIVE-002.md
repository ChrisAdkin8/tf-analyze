# ⚠️ SEC-SENSITIVE-002 — Sensitive marker dropped at module boundary

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Sensitive marker dropped at module boundary.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`cross_module`** — _a `cross_module` pattern._
  A sensitive variable in a parent module is passed to a child
module input whose corresponding variable is NOT marked sensitive.

## Why it likely fired

A sensitive variable in a parent module is passed to a child
module input whose corresponding variable is NOT marked sensitive.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-SENSITIVE-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add `sensitive = true` to the child module's variable declaration.
Sensitivity does not propagate automatically across module boundaries
— each variable in each module must be marked independently.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
# In the child module — mark the variable sensitive
variable "db_password" {
  type        = string
  description = "Database password"
  sensitive   = true
}
```

## Verification

Run `terraform plan` in the parent and confirm the value is shown
as `<sensitive>` in any module output that references the variable.

## References

**MITRE ATT&CK**
  - [`T1552.001`](https://attack.mitre.org/techniques/T1552/001/)

**Source**
  - [`catalog/SEC-SENSITIVE-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-SENSITIVE-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-SENSITIVE-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-SENSITIVE-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-SENSITIVE-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
