# 🚨 SEC-AWS-IAM-POLICY-005 — IAM policy grants both `actions = [\"*\"]` and `resources = [\"*\"]`

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **IAM policy grants both `actions = [\"*\"]` and `resources = [\"*\"]`.** This rule has `default_urgency: CRITICAL` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`iam_policy_analysis`** — check: `wildcard_action_and_resource` — _a `data "aws_iam_policy_document"` Allow statement matches the listed check._
  Single statement grants `actions = ["*"]` *and* `resources = ["*"]`
with effect Allow. This is the canonical "AdministratorAccess"
shape — equivalent to attaching the AWS-managed Administrator
policy by hand-rolled means and bypassing org-level guardrails
that detect the named policy.

## Why it likely fired

Single statement grants `actions = ["*"]` *and* `resources = ["*"]`
with effect Allow. This is the canonical "AdministratorAccess"
shape — equivalent to attaching the AWS-managed Administrator
policy by hand-rolled means and bypassing org-level guardrails
that detect the named policy.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-IAM-POLICY-005` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

If true administrator access is intentional, attach
`arn:aws:iam::aws:policy/AdministratorAccess` directly via
`aws_iam_role_policy_attachment` so audit and least-privilege tools
flag it correctly. Otherwise, replace with the explicit minimum
action and resource set the workload needs.

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

No policy statement should combine `Action: "*"` and `Resource: "*"`.
CloudTrail data events on this principal should narrow to a small
set of services after the fix.

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
  - [`catalog/SEC-AWS-IAM-POLICY-005.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-IAM-POLICY-005.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-IAM-POLICY-005    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-IAM-POLICY-005` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-IAM-POLICY-005
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
