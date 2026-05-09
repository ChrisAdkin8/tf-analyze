# ⚠️ SEC-AWS-IAM-001 — IAM policy with wildcard resource

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **IAM policy with wildcard resource.** This rule has `default_urgency: HIGH` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`grep`** matching `/"Resource"\s*:\s*"\*"/` — _a textual regex matched somewhere in the file._
  IAM policy document with Resource = "*"
2. **`grep`** matching `/resources\s*=\s*\["\*"\]/` — _a textual regex matched somewhere in the file._
  aws_iam_policy_document statement with resources = ["*"]

## Why it likely fired

IAM policy document with Resource = "*"

aws_iam_policy_document statement with resources = ["*"]

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-IAM-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Narrow the `Resource` field to the specific ARN(s) the policy needs.
Wildcard resources grant the actions to every resource in the account,
violating least-privilege. Use `arn:aws:s3:::my-bucket/*` instead of
`*` for S3 access, `arn:aws:dynamodb:*:*:table/my-table` for DynamoDB,
etc.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
statement {
  actions   = ["s3:GetObject", "s3:PutObject"]
  resources = ["arn:aws:s3:::my-bucket/*"]
}
```

_Narrowing the resource ARN is an in-place policy update; no replacement is required but IAM propagation may take up to 60 seconds._

## Verification

Run `terraform plan` and verify the policy document in the plan output
has no `"Resource": "*"` statements.

## References

**CIS Benchmark**
  - `CIS 1.16`

**PCI-DSS**
  - `Req-7.1`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**MITRE ATT&CK**
  - [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/)

**Source**
  - [`catalog/SEC-AWS-IAM-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-IAM-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-IAM-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-IAM-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-IAM-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
