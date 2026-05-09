# ⚠️ SEC-AWS-IAM-POLICY-003 — IAM policy document grants wildcard `resources = [\"*\"]`

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **IAM policy document grants wildcard `resources = [\"*\"]`.** This rule has `default_urgency: HIGH` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`iam_policy_analysis`** — check: `wildcard_resource` — _a `data "aws_iam_policy_document"` Allow statement matches the listed check._
  A statement inside `data "aws_iam_policy_document"` grants
`resources = ["*"]`. Combined with any non-trivial action set,
this lets the principal touch every matching resource in the
account, not just the ones it owns.

## Why it likely fired

A statement inside `data "aws_iam_policy_document"` grants
`resources = ["*"]`. Combined with any non-trivial action set,
this lets the principal touch every matching resource in the
account, not just the ones it owns.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-IAM-POLICY-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Scope `resources` to specific ARNs or ARN patterns. For S3 use
`arn:aws:s3:::my-bucket/*`; for KMS use the key ARN; for EC2 use
`arn:aws:ec2:<region>:<account>:instance/i-*` filtered by tag
conditions.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
data "aws_iam_policy_document" "example" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::my-bucket/*"]
  }
}
```

## Verification

The rendered policy's `Resource` field must be a finite list of
ARNs, not `"*"`.

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
  - [`catalog/SEC-AWS-IAM-POLICY-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-IAM-POLICY-003.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-IAM-POLICY-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-IAM-POLICY-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-IAM-POLICY-003
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
