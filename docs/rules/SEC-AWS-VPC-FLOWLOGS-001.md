# ⚠️ SEC-AWS-VPC-FLOWLOGS-001 — AWS VPC missing flow log resource

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **AWS VPC missing flow log resource.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_absent`** on `aws_flow_log` — _the corpus is missing a resource type we expected to find given other resources present._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-VPC-FLOWLOGS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add an `aws_flow_log` resource targeting every VPC:

    resource "aws_flow_log" "vpc" {
      vpc_id          = aws_vpc.main.id
      traffic_type    = "ALL"
      iam_role_arn    = aws_iam_role.flow_log.arn
      log_destination = aws_cloudwatch_log_group.flow_log.arn
    }

VPC flow logs are the primary network-layer evidence source for
post-incident investigation and anomaly detection. Without them,
lateral movement within the VPC is invisible.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_flow_log" "example" {
  vpc_id          = aws_vpc.example.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_log.arn
  log_destination = aws_cloudwatch_log_group.flow_log.arn
}
```

## Verification

In the AWS console, VPC → Your VPCs → select VPC → Flow logs tab.
At least one active flow log must be present. Or:
`aws ec2 describe-flow-logs --filter Name=resource-id,Values=<vpc-id>`

## References

**CIS Benchmark**
  - `CIS 3.9`

**MITRE ATT&CK**
  - [`T1562.008`](https://attack.mitre.org/techniques/T1562/008/)

**Source**
  - [`catalog/SEC-AWS-VPC-FLOWLOGS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-VPC-FLOWLOGS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-VPC-FLOWLOGS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-VPC-FLOWLOGS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-VPC-FLOWLOGS-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
