# 💡 SEC-AWS-ATHENA-001 — Athena workgroup results not encrypted

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Athena workgroup results not encrypted.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_athena_workgroup` (`encryption_option`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_athena_workgroup` has no `encryption_configuration` in its
`result_configuration` block. Query results written to S3 use
SSE-S3 by default but this can be overridden by individual users.
Locking encryption at the workgroup level with SSE-KMS ensures
results are always encrypted with a customer-controlled key and
the setting cannot be bypassed.

## Why it likely fired

`aws_athena_workgroup` has no `encryption_configuration` in its
`result_configuration` block. Query results written to S3 use
SSE-S3 by default but this can be overridden by individual users.
Locking encryption at the workgroup level with SSE-KMS ensures
results are always encrypted with a customer-controlled key and
the setting cannot be bypassed.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-ATHENA-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enforce SSE-KMS encryption at the workgroup level:

    resource "aws_athena_workgroup" "main" {
      name = "main"
      configuration {
        enforce_workgroup_configuration = true
        result_configuration {
          output_location = "s3://${aws_s3_bucket.results.bucket}/output/"
          encryption_configuration {
            encryption_option = "SSE_KMS"
            kms_key_arn       = aws_kms_key.athena.arn
          }
        }
      }
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_athena_workgroup" "example" {
  name = "example"
  configuration {
    enforce_workgroup_configuration = true
    result_configuration {
      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.athena.arn
      }
    }
  }
}
```

## Verification

```sh
`aws athena get-work-group --work-group <name> \
  --query 'WorkGroup.Configuration.ResultConfiguration.EncryptionConfiguration.EncryptionOption'`
must return `"SSE_KMS"`.
```

## References

**PCI-DSS**
  - `Req-3.4`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**Source**
  - [`catalog/SEC-AWS-ATHENA-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-ATHENA-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-ATHENA-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-ATHENA-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-ATHENA-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
