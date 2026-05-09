# ⚠️ ROB-AWS-RDS-003 — RDS instance or Aurora cluster missing deletion protection

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **RDS instance or Aurora cluster missing deletion protection.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_db_instance` (`deletion_protection`) — _the resource is missing a required attribute (or nested attribute path)._
  RDS instance without deletion_protection. A terraform destroy or
accidental module removal will permanently delete the database
without any safeguard.
2. **`hcl_attr`** on `aws_db_instance` (`deletion_protection`) not equal to `True` — _an attribute value differs from the expected literal._
  deletion_protection = false explicitly removes the guard against
accidental database deletion.
3. **`resource_missing_arg`** on `aws_rds_cluster` (`deletion_protection`) — _the resource is missing a required attribute (or nested attribute path)._
  Aurora cluster without deletion_protection. Cluster deletion destroys
all cluster instances and their data.
4. **`hcl_attr`** on `aws_rds_cluster` (`deletion_protection`) not equal to `True` — _an attribute value differs from the expected literal._
  Aurora cluster deletion_protection = false explicitly removes the guard.

## Why it likely fired

RDS instance without deletion_protection. A terraform destroy or
accidental module removal will permanently delete the database
without any safeguard.

deletion_protection = false explicitly removes the guard against
accidental database deletion.

Aurora cluster without deletion_protection. Cluster deletion destroys
all cluster instances and their data.

Aurora cluster deletion_protection = false explicitly removes the guard.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-AWS-RDS-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `deletion_protection = true` on every production RDS instance:

    resource "aws_db_instance" "app" {
      deletion_protection = true
      # ...
    }

Pair with `lifecycle { prevent_destroy = true }` in Terraform for a
two-layer guard: AWS-level deletion protection requires a manual disable
step before destruction, while the lifecycle hook prevents `terraform
destroy` from even attempting it.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_db_instance" "example" {
  # ... other arguments ...
  deletion_protection = true
}
```

## Verification

```sh
`aws rds describe-db-instances --db-instance-identifier <id> \
  --query 'DBInstances[0].DeletionProtection'`
must return `true`.
```

## References

**SOC 2 Trust Services Criteria**
  - `A1.2`

**Source**
  - [`catalog/ROB-AWS-RDS-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-AWS-RDS-003.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-AWS-RDS-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-AWS-RDS-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-AWS-RDS-003
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
