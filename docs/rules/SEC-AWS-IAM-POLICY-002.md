# 🚨 SEC-AWS-IAM-POLICY-002 — IAM policy document grants wildcard `iam:*` actions

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **IAM policy document grants wildcard `iam:*` actions.** This rule has `default_urgency: CRITICAL` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`iam_policy_analysis`** — check: `wildcard_action_iam` — _a `data "aws_iam_policy_document"` Allow statement matches the listed check._
  Statement grants an `iam:*` wildcard action (e.g. `iam:Create*`,
`iam:*`). This class of grant lets the principal create or attach
policies to itself, escalating to full administrative access.

## Why it likely fired

Statement grants an `iam:*` wildcard action (e.g. `iam:Create*`,
`iam:*`). This class of grant lets the principal create or attach
policies to itself, escalating to full administrative access.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-IAM-POLICY-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace `iam:*` with the explicit IAM operations actually required.
If full IAM access is intentional, use the AWS-managed
`IAMFullAccess` policy and bind it via `aws_iam_user_policy_attachment`
rather than embedding the wildcard inline.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
data "aws_iam_policy_document" "example" {
  statement {
    effect    = "Allow"
    actions   = ["iam:GetUser", "iam:ListAttachedUserPolicies"]
    resources = ["arn:aws:iam::*:user/$${aws:username}"]
  }
}
```

## Verification

Inspect the policy's effective Action list — no entry should contain
the literal `iam:` prefix combined with `*`.

## References

**CIS Benchmark**
  - `CIS 1.16`

**PCI-DSS**
  - `Req-7.2.2`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**MITRE ATT&CK**
  - [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/)
  - [`T1098.001`](https://attack.mitre.org/techniques/T1098/001/)

**Source**
  - [`catalog/SEC-AWS-IAM-POLICY-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-IAM-POLICY-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-IAM-POLICY-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-IAM-POLICY-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-IAM-POLICY-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
