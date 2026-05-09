# 💡 SEC-AWS-WAF-001 — WAFv2 web ACL missing logging configuration

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **WAFv2 web ACL missing logging configuration.** This rule has `default_urgency: MEDIUM` and operates on a module blast radius. 

## What this checks

1. **`resource_absent`** on `aws_wafv2_logging_configuration` — _the corpus is missing a resource type we expected to find given other resources present._
  `aws_wafv2_web_acl` exists but no `aws_wafv2_logging_configuration`
is defined. Without logging, blocked and allowed requests are invisible:
you cannot investigate incidents, tune rules to reduce false positives,
or demonstrate compliance with audit requirements. WAF logging streams
to an S3 bucket, CloudWatch Logs, or Kinesis Firehose at no additional
charge beyond storage costs.

## Why it likely fired

`aws_wafv2_web_acl` exists but no `aws_wafv2_logging_configuration`
is defined. Without logging, blocked and allowed requests are invisible:
you cannot investigate incidents, tune rules to reduce false positives,
or demonstrate compliance with audit requirements. WAF logging streams
to an S3 bucket, CloudWatch Logs, or Kinesis Firehose at no additional
charge beyond storage costs.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-WAF-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a `aws_wafv2_logging_configuration` resource for every WAF ACL:

    resource "aws_kinesis_firehose_delivery_stream" "waf" {
      name        = "aws-waf-logs-app"
      destination = "extended_s3"

      extended_s3_configuration {
        role_arn   = aws_iam_role.firehose.arn
        bucket_arn = aws_s3_bucket.waf_logs.arn
      }
    }

    resource "aws_wafv2_logging_configuration" "app" {
      log_destination_configs = [aws_kinesis_firehose_delivery_stream.waf.arn]
      resource_arn            = aws_wafv2_web_acl.app.arn
    }

The log destination name must start with `aws-waf-logs-`. WAF logs
include the full request, matched rules, action taken, and timestamps.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_wafv2_logging_configuration" "example" {
  log_destination_configs = [aws_kinesis_firehose_delivery_stream.waf.arn]
  resource_arn            = aws_wafv2_web_acl.example.arn
}
```

## Verification

```sh
`aws wafv2 get-logging-configuration \
  --resource-arn <acl-arn> --scope REGIONAL`
must return a logging configuration with at least one destination.
```

## References

**MITRE ATT&CK**
  - [`T1562.004`](https://attack.mitre.org/techniques/T1562/004/)

**Source**
  - [`catalog/SEC-AWS-WAF-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-WAF-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-WAF-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-WAF-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-WAF-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
