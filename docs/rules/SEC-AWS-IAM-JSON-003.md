# 🚨 SEC-AWS-IAM-JSON-003 — Inline IAM policy JSON grants `Action: \"*\"` AND `Resource: \"*\"`

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **Inline IAM policy JSON grants `Action: \"*\"` AND `Resource: \"*\"`.** This rule has `default_urgency: CRITICAL` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`iam_json_policy_analysis`** — check: `wildcard_action_and_resource` — _an inline `policy = jsonencode({...})` Allow statement matches the listed check._
  Inline JSON policy contains a single Allow statement granting
both `Action: "*"` and `Resource: "*"` — the canonical
AdministratorAccess shape, hand-rolled inline rather than via
the named AWS-managed policy. Bypasses org-level controls and
audit tools that recognise `AdministratorAccess`.

## Why it likely fired

Inline JSON policy contains a single Allow statement granting
both `Action: "*"` and `Resource: "*"` — the canonical
AdministratorAccess shape, hand-rolled inline rather than via
the named AWS-managed policy. Bypasses org-level controls and
audit tools that recognise `AdministratorAccess`.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-IAM-JSON-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

If true administrator access is intended, attach
`arn:aws:iam::aws:policy/AdministratorAccess` directly via
`aws_iam_role_policy_attachment`. Otherwise, scope to the explicit
minimum action and resource set.

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

No statement in the rendered policy may combine `Action: "*"` and
`Resource: "*"`. CloudTrail data events on this principal should
narrow to a small set of services after the fix.

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
  - [`catalog/SEC-AWS-IAM-JSON-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-IAM-JSON-003.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-IAM-JSON-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-IAM-JSON-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-IAM-JSON-003
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
