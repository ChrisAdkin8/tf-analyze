# 💡 SEC-AWS-S3-LOGGING-001 — S3 bucket missing server access logging

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **S3 bucket missing server access logging.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_absent`** on `aws_s3_bucket_logging` — _the corpus is missing a resource type we expected to find given other resources present._
  Repository contains `aws_s3_bucket` resources but no
`aws_s3_bucket_logging` resource. S3 server access logs record every
request made to a bucket — GETs, PUTs, DELETEs — and are the primary
evidence source for post-incident investigation and compliance auditing.
CIS AWS Foundations Benchmark §3.6 requires server access logging
enabled on all S3 buckets used to store CloudTrail logs; broader
best practice is to enable it on every bucket.

Without access logs, questions like "who downloaded this object?",
"when was this object deleted?", or "is there unusual GET activity from
an unexpected IP?" have no answer.

## Why it likely fired

Repository contains `aws_s3_bucket` resources but no
`aws_s3_bucket_logging` resource. S3 server access logs record every
request made to a bucket — GETs, PUTs, DELETEs — and are the primary
evidence source for post-incident investigation and compliance auditing.
CIS AWS Foundations Benchmark §3.6 requires server access logging
enabled on all S3 buckets used to store CloudTrail logs; broader
best practice is to enable it on every bucket.

Without access logs, questions like "who downloaded this object?",
"when was this object deleted?", or "is there unusual GET activity from
an unexpected IP?" have no answer.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-S3-LOGGING-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a dedicated logging bucket and enable access logging on every bucket
that requires audit trails:

```hcl
resource "aws_s3_bucket" "logs" {
  bucket = "${var.prefix}-access-logs"
}

resource "aws_s3_bucket_logging" "app" {
  bucket        = aws_s3_bucket.app.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "app-access-logs/"
}
```

The logging bucket itself does not need a logging configuration (that
would create a loop). Protect the logging bucket with:
- `aws_s3_bucket_public_access_block` (block all public access)
- `lifecycle_rule` with expiration (keep logs ≥90 days for CIS)
- `aws_s3_bucket_server_side_encryption_configuration`

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_s3_bucket_logging" "example" {
  bucket        = aws_s3_bucket.example.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "access-logs/"
}
```

## Verification

```sh
`aws s3api get-bucket-logging --bucket <name>` must return a
`LoggingEnabled` key. After applying, confirm logs appear in the
target bucket within a few minutes of S3 activity.
```

## References

**CIS Benchmark**
  - `CIS 3.6`

**MITRE ATT&CK**
  - [`T1562.008`](https://attack.mitre.org/techniques/T1562/008/)

**Source**
  - [`catalog/SEC-AWS-S3-LOGGING-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-S3-LOGGING-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-S3-LOGGING-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-S3-LOGGING-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-S3-LOGGING-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
