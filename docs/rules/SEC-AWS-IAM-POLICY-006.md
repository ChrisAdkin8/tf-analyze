# 💡 SEC-AWS-IAM-POLICY-006 — IAM policy uses `not_actions` or `not_resources`

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **IAM policy uses `not_actions` or `not_resources`.** This rule has `default_urgency: MEDIUM` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`iam_policy_analysis`** — check: `not_action_or_not_resource` — _a `data "aws_iam_policy_document"` Allow statement matches the listed check._
  Statement uses `not_actions` or `not_resources` to express
"everything except X". Negative-form grants are notoriously
error-prone: any new AWS API or resource type added in future
is implicitly allowed. AWS itself recommends against negative
form for Allow statements.

## Why it likely fired

Statement uses `not_actions` or `not_resources` to express
"everything except X". Negative-form grants are notoriously
error-prone: any new AWS API or resource type added in future
is implicitly allowed. AWS itself recommends against negative
form for Allow statements.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-IAM-POLICY-006` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Rewrite the statement using `actions` and `resources` to enumerate
the explicit allow set. Reserve `not_actions` / `not_resources` for
Deny statements (a defensive deny is safe to phrase negatively).

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
data "aws_iam_policy_document" "example" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["arn:aws:s3:::my-bucket/*"]
  }
}
```

## Verification

Policy statements with `Effect: Allow` should not contain `NotAction`
or `NotResource`.

## References

**CIS Benchmark**
  - `CIS 1.16`

**PCI-DSS**
  - `Req-7.2.2`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**MITRE ATT&CK**
  - [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/)

**Source**
  - [`catalog/SEC-AWS-IAM-POLICY-006.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-IAM-POLICY-006.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-IAM-POLICY-006    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-IAM-POLICY-006` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-IAM-POLICY-006
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
