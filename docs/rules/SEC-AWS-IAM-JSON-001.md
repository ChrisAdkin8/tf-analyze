# ⚠️ SEC-AWS-IAM-JSON-001 — Inline IAM policy JSON grants wildcard `Action: \"*\"`

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **Inline IAM policy JSON grants wildcard `Action: \"*\"`.** This rule has `default_urgency: HIGH` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`iam_json_policy_analysis`** — check: `wildcard_action` — _an inline `policy = jsonencode({...})` Allow statement matches the listed check._
  An inline `policy = jsonencode({...})` on `aws_iam_policy`,
`aws_iam_role_policy`, `aws_iam_user_policy`, or
`aws_iam_group_policy` declares an Allow statement with
`Action: "*"`. The principal bound to this policy can perform
any AWS API call against the scoped resources — the canonical
privilege-escalation foothold.

## Why it likely fired

An inline `policy = jsonencode({...})` on `aws_iam_policy`,
`aws_iam_role_policy`, `aws_iam_user_policy`, or
`aws_iam_group_policy` declares an Allow statement with
`Action: "*"`. The principal bound to this policy can perform
any AWS API call against the scoped resources — the canonical
privilege-escalation foothold.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-IAM-JSON-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace `Action: "*"` with the explicit minimum API set the workload
requires. Use `aws iam simulate-principal-policy` to validate that
the trimmed list still passes for legitimate flows.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_iam_policy" "example" {
  name   = "example"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["s3:GetObject", "s3:PutObject"],
        Resource = "arn:aws:s3:::my-bucket/*"
      }
    ]
  })
}
```

## Verification

```sh
`aws iam get-policy-version --policy-arn <arn> --version-id v1
  --query 'PolicyVersion.Document.Statement[*].Action'`
must return finite lists, never `"*"`.
```

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
  - [`catalog/SEC-AWS-IAM-JSON-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-IAM-JSON-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-IAM-JSON-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-IAM-JSON-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-IAM-JSON-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
