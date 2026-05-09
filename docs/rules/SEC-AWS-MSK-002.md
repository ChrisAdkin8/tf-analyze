# 💡 SEC-AWS-MSK-002 — MSK cluster does not use CMK for encryption at rest

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **MSK cluster does not use CMK for encryption at rest.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_msk_cluster` (`encryption_at_rest_kms_key_arn`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_msk_cluster` has no `encryption_at_rest_kms_key_arn`. Without a
customer-managed KMS key (CMK), MSK uses an AWS-managed key that cannot
be audited, rotated on a custom schedule, or revoked in incident response.

## Why it likely fired

`aws_msk_cluster` has no `encryption_at_rest_kms_key_arn`. Without a
customer-managed KMS key (CMK), MSK uses an AWS-managed key that cannot
be audited, rotated on a custom schedule, or revoked in incident response.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-MSK-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Provide a CMK for storage encryption:

    resource "aws_msk_cluster" "main" {
      # ...
      encryption_info {
        encryption_at_rest {
          encryption_at_rest_kms_key_arn = aws_kms_key.msk.arn
        }
      }
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "aws_msk_cluster" "example" {
  cluster_name = "example"
  encryption_info {
    encryption_at_rest {
      encryption_at_rest_kms_key_arn = aws_kms_key.msk.arn
    }
  }
}
```

## Verification

```sh
`aws kafka describe-cluster --cluster-arn <arn> \
  --query 'ClusterInfo.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId'`
must return a KMS key ARN.
```

## References

**PCI-DSS**
  - `Req-3.4`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**Source**
  - [`catalog/SEC-AWS-MSK-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-MSK-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-MSK-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-MSK-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-MSK-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
