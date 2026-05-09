# ⚠️ SEC-SENSITIVE-001 — Sensitive output not marked sensitive=true

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Sensitive output not marked sensitive=true.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`output_sensitive_leak`** — _a `output_sensitive_leak` pattern._
  Output value references a variable marked sensitive=true but the
output itself does not have sensitive=true.

## Why it likely fired

Output value references a variable marked sensitive=true but the
output itself does not have sensitive=true.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-SENSITIVE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add `sensitive = true` to the output block. Without this marker the
value appears in `terraform plan` and `terraform output` console
output and may end up in CI logs.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
output "db_password" {
  value     = module.db.password
  sensitive = true
}
```

## Verification

Run `terraform output <name>` and confirm the value is masked as
`<sensitive>`. Re-run tf-analyze in mode:verify-fixed.

## References

**MITRE ATT&CK**
  - [`T1552.001`](https://attack.mitre.org/techniques/T1552/001/)

**Source**
  - [`catalog/SEC-SENSITIVE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-SENSITIVE-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-SENSITIVE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-SENSITIVE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-SENSITIVE-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
