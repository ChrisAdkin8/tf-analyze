# 🚨 SEC-AWS-IAM-POLICY-004 — IAM policy document grants principal `identifiers = [\"*\"]` (public)

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **IAM policy document grants principal `identifiers = [\"*\"]` (public).** This rule has `default_urgency: CRITICAL` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`iam_policy_analysis`** — check: `public_principal` — _a `data "aws_iam_policy_document"` Allow statement matches the listed check._
  A statement uses `principals { identifiers = ["*"] }` (or any
principal whose identifiers list contains `"*"`). The policy
grants the action set to *any* principal — effectively making
whatever resource it attaches to public (S3 buckets, SNS topics,
KMS keys, Secrets Manager secrets all support resource policies).

## Why it likely fired

A statement uses `principals { identifiers = ["*"] }` (or any
principal whose identifiers list contains `"*"`). The policy
grants the action set to *any* principal — effectively making
whatever resource it attaches to public (S3 buckets, SNS topics,
KMS keys, Secrets Manager secrets all support resource policies).

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-IAM-POLICY-004` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace the wildcard principal with the specific account or role
ARNs that should have access. If true public exposure is the
intent (e.g. a website-hosting bucket), use the resource-specific
public-access mechanism (`aws_s3_bucket_policy` with explicit
`Principal: "*"` *plus* documented intent) and gate it with a
`aws_s3_bucket_public_access_block` exception.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
data "aws_iam_policy_document" "example" {
  statement {
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }
  }
}
```

## Verification

The rendered policy's `Principal` field must be a structured
object listing AWS account IDs or service principals, not `"*"`.

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
  - [`catalog/SEC-AWS-IAM-POLICY-004.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-IAM-POLICY-004.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-IAM-POLICY-004    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-IAM-POLICY-004` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-IAM-POLICY-004
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
