# ⚠️ SEC-AWS-IAM-POLICY-001 — IAM policy document grants wildcard `actions = [\"*\"]`

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **IAM policy document grants wildcard `actions = [\"*\"]`.** This rule has `default_urgency: HIGH` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`iam_policy_analysis`** — check: `wildcard_action` — _a `data "aws_iam_policy_document"` Allow statement matches the listed check._
  A statement inside `data "aws_iam_policy_document"` grants `actions = ["*"]`.
Effective grant is "any AWS API call against any resource selected
by this policy" — the canonical privilege-escalation foothold.

## Why it likely fired

A statement inside `data "aws_iam_policy_document"` grants `actions = ["*"]`.
Effective grant is "any AWS API call against any resource selected
by this policy" — the canonical privilege-escalation foothold.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-IAM-POLICY-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace `actions = ["*"]` with the explicit minimum set the workload
requires. Use `aws iam simulate-principal-policy` to validate that
the trimmed list still passes for legitimate flows.

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

Re-render the policy with `terraform plan` and inspect the rendered
`Action` field — it must be a finite list, not `"*"`.

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
  - [`catalog/SEC-AWS-IAM-POLICY-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-IAM-POLICY-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-IAM-POLICY-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-IAM-POLICY-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-IAM-POLICY-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
