# 💡 ROB-REMOTESTATE-001 — terraform_remote_state data source couples modules implicitly

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **terraform_remote_state data source couples modules implicitly.** This rule has `default_urgency: MEDIUM` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`remote_state_present`** — _a `remote_state_present` pattern._
  data "terraform_remote_state" couples this config to another root's state layout

## Why it likely fired

data "terraform_remote_state" couples this config to another root's state layout

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-REMOTESTATE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace `data.terraform_remote_state` with an explicit interface — either
module outputs passed via `inputs`, or provider data sources that read the
underlying resource by attribute (e.g., `data.google_storage_bucket.x`).

terraform_remote_state has two failure modes that bite in production:
 1. A rename of the upstream output (non-breaking at its producer) becomes
    a plan-time failure here, with a message pointing nowhere useful.
 2. Callers need read access to the upstream state bucket, which
    over-scopes IAM (the bucket contains secrets in .tfstate attributes).

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
data "aws_ssm_parameter" "vpc_id" {
  name = "/networking/vpc_id"
}
locals {
  vpc_id = data.aws_ssm_parameter.vpc_id.value
}
```

## Verification

Grep for `data "terraform_remote_state"` under the scanned path — zero hits.
If the replacement uses provider data sources, run `terraform plan` and
confirm the same values resolve.

## References

**Source**
  - [`catalog/ROB-REMOTESTATE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-REMOTESTATE-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-REMOTESTATE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-REMOTESTATE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-REMOTESTATE-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
