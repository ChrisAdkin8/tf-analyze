# 💡 SEC-AWS-DDB-001 — DynamoDB table not using customer-managed KMS key for encryption

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **DynamoDB table not using customer-managed KMS key for encryption.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`graph_check`** — _a corpus-wide graph check fired (cross-resource invariant)._
  `aws_dynamodb_table` without a `server_side_encryption` block
specifying a `kms_key_arn`. DynamoDB encrypts at rest by default
using Amazon-owned keys, but these keys cannot be audited, rotated,
or revoked. Customer-managed KMS keys (CMKs) provide key usage audit
trails in CloudTrail, cross-account access control, and automatic
annual rotation.

## Why it likely fired

`aws_dynamodb_table` without a `server_side_encryption` block
specifying a `kms_key_arn`. DynamoDB encrypts at rest by default
using Amazon-owned keys, but these keys cannot be audited, rotated,
or revoked. Customer-managed KMS keys (CMKs) provide key usage audit
trails in CloudTrail, cross-account access control, and automatic
annual rotation.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-DDB-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a `server_side_encryption` block with a customer-managed KMS key:

    resource "aws_kms_key" "ddb" {
      description             = "DynamoDB table CMK"
      deletion_window_in_days = 30
      enable_key_rotation     = true
    }

    resource "aws_dynamodb_table" "app" {
      name = "app"

      server_side_encryption {
        enabled     = true
        kms_key_arn = aws_kms_key.ddb.arn
      }
    }

If a CMK is not yet available, the minimum acceptable baseline is
`server_side_encryption { enabled = true }` (AWS-managed key), which
at least makes the encryption choice explicit rather than implicit.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_dynamodb_table" "example" {
  name = "example"

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.ddb.arn
  }
}
```

## Verification

```sh
`aws dynamodb describe-table --table-name <name> \
  --query 'Table.SSEDescription'`
must return `Status: ENABLED` with a `KMSMasterKeyArn` value pointing
to a customer-managed key (not the AWS-owned key ARN).
```

## References

**PCI-DSS**
  - `Req-3.4`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**MITRE ATT&CK**
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)

**Source**
  - [`catalog/SEC-AWS-DDB-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-DDB-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-DDB-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-DDB-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-DDB-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
