# 💡 SEC-AWS-CWL-001 — CloudWatch log group not encrypted with KMS CMK

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **CloudWatch log group not encrypted with KMS CMK.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_cloudwatch_log_group` (`kms_key_id`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_cloudwatch_log_group` has no `kms_key_id`. Without a customer-managed
KMS key, log data is encrypted with an AWS-managed key that cannot be
independently revoked, audited, or rotated. Logs often contain sensitive
application data, credentials in error traces, and PII that requires
customer-controlled encryption.

## Why it likely fired

`aws_cloudwatch_log_group` has no `kms_key_id`. Without a customer-managed
KMS key, log data is encrypted with an AWS-managed key that cannot be
independently revoked, audited, or rotated. Logs often contain sensitive
application data, credentials in error traces, and PII that requires
customer-controlled encryption.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-CWL-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Encrypt every log group with a CMK:

    resource "aws_cloudwatch_log_group" "app" {
      name              = "/app/prod"
      retention_in_days = 90
      kms_key_id        = aws_kms_key.logs.arn
    }

The KMS key policy must grant `logs.<region>.amazonaws.com` permission to
call `kms:Encrypt`, `kms:Decrypt`, and `kms:GenerateDataKey`.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_cloudwatch_log_group" "example" {
  name              = "example"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.logs.arn
}
```

## Verification

```sh
`aws logs describe-log-groups --log-group-name-prefix /app \
  --query 'logGroups[*].kmsKeyId'`
must return a KMS key ARN for every group.
```

## References

**PCI-DSS**
  - `Req-3.4`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**MITRE ATT&CK**
  - [`T1562.008`](https://attack.mitre.org/techniques/T1562/008/)

**Source**
  - [`catalog/SEC-AWS-CWL-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-CWL-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-CWL-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-CWL-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-CWL-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
