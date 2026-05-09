# ⚠️ SEC-AWS-RDS-002 — RDS instance or Aurora cluster storage not encrypted

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **RDS instance or Aurora cluster storage not encrypted.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_db_instance` (`storage_encrypted`) — _the resource is missing a required attribute (or nested attribute path)._
  RDS instance missing storage_encrypted (defaults to false)
2. **`resource_arg`** on `aws_db_instance` (`storage_encrypted`) matching `/^false$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  RDS instance with storage_encrypted = false
3. **`resource_missing_arg`** on `aws_rds_cluster` (`storage_encrypted`) — _the resource is missing a required attribute (or nested attribute path)._
  Aurora cluster missing storage_encrypted (defaults to false)
4. **`resource_arg`** on `aws_rds_cluster` (`storage_encrypted`) matching `/^false$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Aurora cluster with storage_encrypted = false

## Why it likely fired

RDS instance missing storage_encrypted (defaults to false)

RDS instance with storage_encrypted = false

Aurora cluster missing storage_encrypted (defaults to false)

Aurora cluster with storage_encrypted = false

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-RDS-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `storage_encrypted = true` and provide a `kms_key_id` pointing to a
customer-managed KMS key on every `aws_db_instance`. Encrypting storage
at rest protects data from physical media theft and satisfies PCI-DSS,
HIPAA, and SOC 2 controls. Note: encryption cannot be enabled on an
existing unencrypted instance — you must snapshot, restore to a new
encrypted instance, and redirect traffic.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "aws_db_instance" "example" {
  # ... other arguments ...
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
}
```

_Storage encryption cannot be enabled on an existing RDS instance — requires snapshot + restore to a new encrypted instance and traffic cutover._

## Verification

Run `aws rds describe-db-instances --db-instance-identifier <id>` and
confirm `StorageEncrypted` is `true`. Run `terraform plan` and verify
no diff shows `storage_encrypted = false`.

## References

**CIS Benchmark**
  - `CIS 2.3.1`

**PCI-DSS**
  - `Req-3.4`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**Source**
  - [`catalog/SEC-AWS-RDS-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-RDS-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-RDS-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-RDS-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-RDS-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
