# ⚠️ SEC-SENSITIVE-003 — Sensitive variable passed to templatefile()

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Sensitive variable passed to templatefile().** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`templatefile_sensitive_leak`** — _a `templatefile()` call passes a sensitive variable to a template._
  templatefile() call whose argument map references a sensitive variable, rendering the secret into a non-sensitive string

## Why it likely fired

templatefile() call whose argument map references a sensitive variable, rendering the secret into a non-sensitive string

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-SENSITIVE-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Avoid passing sensitive variables through `templatefile()`. The
rendered output is a plain string that Terraform does NOT mark as
sensitive, so it appears in plans, state, and logs.

Instead, use a `local` to construct the sensitive portion separately
and mark it `sensitive = true`, or use `nonsensitive()` explicitly
to acknowledge the exposure.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
# Separate sensitive values — don't pass them through templatefile()
locals {
  # Non-sensitive config rendered by templatefile
  user_data = templatefile("${path.module}/init.sh.tpl", {
    region = var.region
    name   = var.name
  })
}

# Pass password separately via a write_only argument or secrets manager reference
resource "aws_instance" "app" {
  user_data = local.user_data
  # password is injected via metadata or secrets manager, not template
}
```

## Verification

Run `terraform plan` and check that the rendered template value
shows as `(sensitive value)` in the plan output. If it shows in
cleartext, the leak is confirmed.

## References

**MITRE ATT&CK**
  - [`T1552.001`](https://attack.mitre.org/techniques/T1552/001/)

**Source**
  - [`catalog/SEC-SENSITIVE-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-SENSITIVE-003.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-SENSITIVE-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-SENSITIVE-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-SENSITIVE-003
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
