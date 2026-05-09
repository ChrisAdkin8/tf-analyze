# ⚠️ SEC-AWS-GUARDDUTY-001 — GuardDuty detector not provisioned

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **GuardDuty detector not provisioned.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`resource_absent`** on `aws_guardduty_detector` — _the corpus is missing a resource type we expected to find given other resources present._
  No `aws_guardduty_detector` is provisioned. GuardDuty uses machine-learning
and threat intelligence to detect account compromise, instance compromise,
and data exfiltration in real time. Without it, there is no continuous
monitoring of CloudTrail, VPC Flow Logs, and DNS logs for malicious activity.
GuardDuty is a prerequisite for Security Hub aggregation and many compliance
frameworks.

## Why it likely fired

No `aws_guardduty_detector` is provisioned. GuardDuty uses machine-learning
and threat intelligence to detect account compromise, instance compromise,
and data exfiltration in real time. Without it, there is no continuous
monitoring of CloudTrail, VPC Flow Logs, and DNS logs for malicious activity.
GuardDuty is a prerequisite for Security Hub aggregation and many compliance
frameworks.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-GUARDDUTY-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable GuardDuty in every account and region:

    resource "aws_guardduty_detector" "main" {
      enable = true

      datasources {
        s3_logs { enable = true }
        kubernetes { audit_logs { enable = true } }
        malware_protection {
          scan_ec2_instance_with_findings { ebs_volumes { enable = true } }
        }
      }
    }

Use `aws_guardduty_organization_admin_account` to enable GuardDuty
org-wide from the management account.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_guardduty_detector" "main" {
  enable = true
}
```

## Verification

```sh
`aws guardduty list-detectors --query 'DetectorIds'`
must return at least one detector ID.
```

## References

**CIS Benchmark**
  - `CIS 3.3` — Ensure AWS Config is enabled in all regions

**PCI-DSS**
  - `Req-10.6`

**SOC 2 Trust Services Criteria**
  - `CC7.2`

**MITRE ATT&CK**
  - [`T1562.001`](https://attack.mitre.org/techniques/T1562/001/)

**Source**
  - [`catalog/SEC-AWS-GUARDDUTY-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-GUARDDUTY-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-GUARDDUTY-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-GUARDDUTY-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-GUARDDUTY-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
