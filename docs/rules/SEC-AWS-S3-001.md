# ⚠️ SEC-AWS-S3-001 — S3 bucket missing server-side encryption configuration

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **S3 bucket missing server-side encryption configuration.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_s3_bucket_server_side_encryption_configuration` (`rule`) — _the resource is missing a required attribute (or nested attribute path)._
  S3 bucket without encryption configuration resource
2. **`resource_missing_arg`** on `aws_s3_bucket` (`server_side_encryption_configuration.rule`) — _the resource is missing a required attribute (or nested attribute path)._
  S3 bucket with legacy inline encryption block missing (pre-v4 provider)

## Why it likely fired

S3 bucket without encryption configuration resource

S3 bucket with legacy inline encryption block missing (pre-v4 provider)

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-S3-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Create an `aws_s3_bucket_server_side_encryption_configuration` resource
for every S3 bucket, or use the legacy inline block for provider < 4.0.
At minimum, use `AES256` (SSE-S3). For sensitive data, use `aws:kms`
with a customer-managed KMS key.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
```

_Enabling server-side encryption does not re-encrypt existing objects; new objects are encrypted. Requires plan/apply._

## Verification

Run `aws s3api get-bucket-encryption --bucket <name>` and confirm
encryption is enabled.

## References

**CIS Benchmark**
  - `CIS 2.1.1`

**MITRE ATT&CK**
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)

**Source**
  - [`catalog/SEC-AWS-S3-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-S3-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-S3-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-S3-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-S3-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
