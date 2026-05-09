# ℹ️ OPS-AWS-CWL-001 — CloudWatch log group has no retention policy

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: ops](https://img.shields.io/badge/section-ops-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **CloudWatch log group has no retention policy.** This rule has `default_urgency: LOW` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_cloudwatch_log_group` (`retention_in_days`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_cloudwatch_log_group` has no `retention_in_days`. Log groups default
to "Never expire", accumulating data indefinitely. This inflates costs,
complicates log search, and may violate GDPR data-minimisation requirements
by retaining personal data longer than necessary.

## Why it likely fired

`aws_cloudwatch_log_group` has no `retention_in_days`. Log groups default
to "Never expire", accumulating data indefinitely. This inflates costs,
complicates log search, and may violate GDPR data-minimisation requirements
by retaining personal data longer than necessary.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain OPS-AWS-CWL-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set an explicit retention period appropriate to your compliance requirements:

    resource "aws_cloudwatch_log_group" "app" {
      name              = "/app/prod"
      retention_in_days = 90   # 30/60/90/120/150/180/365/400/545/731/1096/1827/2192/2557/2922/3288/3653
    }

Common values: 30 days for transient app logs, 365 days for audit logs,
2557 days (7 years) for financial compliance.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_cloudwatch_log_group" "example" {
  name              = "example"
  retention_in_days = 90
}
```

## Verification

```sh
`aws logs describe-log-groups \
  --query 'logGroups[?!retentionInDays].logGroupName'`
must return an empty list.
```

## References

**SOC 2 Trust Services Criteria**
  - `CC7.2`

**Source**
  - [`catalog/OPS-AWS-CWL-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/OPS-AWS-CWL-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain OPS-AWS-CWL-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore OPS-AWS-CWL-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - OPS-AWS-CWL-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
