# ⚠️ SEC-DATASOURCE-002 — data.external program takes user-controlled input

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **data.external program takes user-controlled input.** This rule has `default_urgency: HIGH` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`data_external_injection`** — _a `data_external_injection` pattern._
  data.external program array includes var/local references — untrusted input reaches a plan-time shell

## Why it likely fired

data.external program array includes var/local references — untrusted input reaches a plan-time shell

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-DATASOURCE-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

`data.external` runs its `program` at plan time with the full privileges
of the Terraform runner. Passing variable- or local-derived arguments
means a Terraform variable can become a shell argument — a supply-chain
gap for operators and CI.

Options:
 1. Replace with a provider data source (`data.http`, `data.aws_*`, etc.).
 2. Hardcode the command and pipe variable data via stdin (map → JSON),
    which `data.external` will pass as stdin. That keeps argv static.
 3. Move the computation to a `null_resource` + `local-exec` with
    `environment = {…}` — still runs something, but at apply time only
    for resources that are being (re)created.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
# Pass variable data via stdin (query map), not via argv
data "external" "lookup" {
  program = ["python3", "${path.module}/scripts/lookup.py"]
  query = {
    environment = var.environment
    region      = var.region
  }
}
```

## Verification

Diff the `program = [ ... ]` array: no `var.*` or `local.*` interpolation
in positions 1..N. If kept, pin the program path to a repo-local script
whose contents are reviewed alongside the Terraform.

## References

**Source**
  - [`catalog/SEC-DATASOURCE-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-DATASOURCE-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-DATASOURCE-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-DATASOURCE-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-DATASOURCE-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
