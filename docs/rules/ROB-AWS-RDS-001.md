# ⚠️ ROB-AWS-RDS-001 — RDS instance or Aurora cluster backup retention disabled

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **RDS instance or Aurora cluster backup retention disabled.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `aws_db_instance` (`backup_retention_period`) matching `/^0$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  RDS instance with backup_retention_period = 0 (backups disabled)
2. **`resource_missing_arg`** on `aws_db_instance` (`backup_retention_period`) — _the resource is missing a required attribute (or nested attribute path)._
  RDS instance missing backup_retention_period (defaults to 0 for non-replica)
3. **`resource_arg`** on `aws_rds_cluster` (`backup_retention_period`) matching `/^0$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Aurora cluster with backup_retention_period = 0 (backups disabled)
4. **`resource_missing_arg`** on `aws_rds_cluster` (`backup_retention_period`) — _the resource is missing a required attribute (or nested attribute path)._
  Aurora cluster missing backup_retention_period (defaults to 1 but should be explicit)

## Why it likely fired

RDS instance with backup_retention_period = 0 (backups disabled)

RDS instance missing backup_retention_period (defaults to 0 for non-replica)

Aurora cluster with backup_retention_period = 0 (backups disabled)

Aurora cluster missing backup_retention_period (defaults to 1 but should be explicit)

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-AWS-RDS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `backup_retention_period` to at least `7` (days) on every
`aws_db_instance`. For production databases, use `30` or more and also
set `delete_automated_backups = false` so that automated backups survive
an accidental instance deletion. Without backups, a corrupted or deleted
database cannot be recovered to a point-in-time prior to the incident.
Also consider enabling `copy_tags_to_snapshot = true` for cost allocation.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_db_instance" "example" {
  # ... other arguments ...
  backup_retention_period = 7
  backup_window           = "03:00-04:00"
}
```

## Verification

Run `aws rds describe-db-instances --db-instance-identifier <id>` and
confirm `BackupRetentionPeriod` is greater than 0. Run `terraform plan`
and verify no diff shows `backup_retention_period = 0` or a missing value.

## References

**SOC 2 Trust Services Criteria**
  - `A1.2`

**Source**
  - [`catalog/ROB-AWS-RDS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-AWS-RDS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-AWS-RDS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-AWS-RDS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-AWS-RDS-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
