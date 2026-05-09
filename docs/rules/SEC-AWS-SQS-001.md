# ⚠️ SEC-AWS-SQS-001 — SQS queue missing server-side encryption

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **SQS queue missing server-side encryption.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_sqs_queue` (`kms_master_key_id`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_sqs_queue` without `kms_master_key_id` and without
`sqs_managed_sse_enabled = true`. Messages at rest are unencrypted.
The finding is suppressed when `sqs_managed_sse_enabled = true`
is present (SQS-managed SSE is an acceptable alternative).

## Why it likely fired

`aws_sqs_queue` without `kms_master_key_id` and without
`sqs_managed_sse_enabled = true`. Messages at rest are unencrypted.
The finding is suppressed when `sqs_managed_sse_enabled = true`
is present (SQS-managed SSE is an acceptable alternative).

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-SQS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable encryption using either a customer-managed KMS key or SQS-managed SSE:

    # Option A — customer-managed KMS (preferred for compliance)
    resource "aws_sqs_queue" "app" {
      name              = "app"
      kms_master_key_id = aws_kms_key.sqs.arn
    }

    # Option B — SQS-managed SSE (simpler, still encrypts at rest)
    resource "aws_sqs_queue" "app" {
      name                    = "app"
      sqs_managed_sse_enabled = true
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_sqs_queue" "example" {
  name              = "example"
  kms_master_key_id = aws_kms_key.sqs.arn
}
```

## Verification

```sh
`aws sqs get-queue-attributes --queue-url <url> \
  --attribute-names KmsMasterKeyId SqsManagedSseEnabled`
must return one of the two attributes set.
```

## References

**PCI-DSS**
  - `Req-3.4`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**Source**
  - [`catalog/SEC-AWS-SQS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-SQS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-SQS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-SQS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-SQS-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
