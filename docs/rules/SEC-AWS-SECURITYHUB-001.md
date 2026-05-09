# 💡 SEC-AWS-SECURITYHUB-001 — Security Hub not enabled

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Security Hub not enabled.** This rule has `default_urgency: MEDIUM` and operates on a module blast radius. 

## What this checks

1. **`resource_absent`** on `aws_securityhub_account` — _the corpus is missing a resource type we expected to find given other resources present._
  No `aws_securityhub_account` resource is defined. Security Hub aggregates
findings from GuardDuty, Inspector, Macie, IAM Access Analyzer, and partner
integrations into a single prioritised view. Without it, security findings
are siloed across services and require manual correlation. Security Hub also
provides AWS Foundational Security Best Practices (FSBP) and CIS benchmark
automated checks.

## Why it likely fired

No `aws_securityhub_account` resource is defined. Security Hub aggregates
findings from GuardDuty, Inspector, Macie, IAM Access Analyzer, and partner
integrations into a single prioritised view. Without it, security findings
are siloed across services and require manual correlation. Security Hub also
provides AWS Foundational Security Best Practices (FSBP) and CIS benchmark
automated checks.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-SECURITYHUB-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable Security Hub and subscribe to relevant standards:

    resource "aws_securityhub_account" "main" {}

    resource "aws_securityhub_standards_subscription" "cis" {
      standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
      depends_on    = [aws_securityhub_account.main]
    }

    resource "aws_securityhub_standards_subscription" "fsbp" {
      standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"
      depends_on    = [aws_securityhub_account.main]
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_securityhub_account" "main" {}
```

## Verification

```sh
`aws securityhub describe-hub --query 'HubArn'`
must return a Hub ARN (non-empty).
```

## References

**PCI-DSS**
  - `Req-10.6`

**SOC 2 Trust Services Criteria**
  - `CC7.2`

**MITRE ATT&CK**
  - [`T1562.001`](https://attack.mitre.org/techniques/T1562/001/)

**Source**
  - [`catalog/SEC-AWS-SECURITYHUB-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-SECURITYHUB-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-SECURITYHUB-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-SECURITYHUB-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-SECURITYHUB-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
