# ⚠️ ROB-AWS-RDS-002 — RDS instance or Aurora cluster skips final snapshot on deletion

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **RDS instance or Aurora cluster skips final snapshot on deletion.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `aws_db_instance` (`skip_final_snapshot`) matching `/^true$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  RDS instance with skip_final_snapshot = true
2. **`resource_arg`** on `aws_rds_cluster` (`skip_final_snapshot`) matching `/^true$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Aurora cluster with skip_final_snapshot = true

## Why it likely fired

RDS instance with skip_final_snapshot = true

Aurora cluster with skip_final_snapshot = true

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-AWS-RDS-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `skip_final_snapshot = false` and provide a `final_snapshot_identifier`
on every production `aws_db_instance`. Without this, running
`terraform destroy` (or any operation that removes the resource from
state) permanently destroys all data in the database with no recovery
path. The final snapshot costs a small amount of S3 storage and is a
last-resort safety net against accidental deletion.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_db_instance" "example" {
  # ... other arguments ...
  skip_final_snapshot       = false
  final_snapshot_identifier = "final-snapshot-${replace(timestamp(), ":", "-")}"
}
```

## Verification

Run `terraform plan -destroy` and confirm Terraform will create a final
snapshot before destroying the instance. Verify via
`aws rds describe-db-snapshots` after any deletion that a final snapshot
was created.

## References

**SOC 2 Trust Services Criteria**
  - `A1.2`

**Source**
  - [`catalog/ROB-AWS-RDS-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-AWS-RDS-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-AWS-RDS-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-AWS-RDS-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-AWS-RDS-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
