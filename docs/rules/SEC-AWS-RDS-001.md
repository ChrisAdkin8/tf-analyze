# ⚠️ SEC-AWS-RDS-001 — RDS instance or Aurora cluster publicly accessible

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **RDS instance or Aurora cluster publicly accessible.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `aws_db_instance` (`publicly_accessible`) matching `/^true$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  RDS instance with publicly_accessible = true
2. **`resource_arg`** on `aws_rds_cluster_instance` (`publicly_accessible`) matching `/^true$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Aurora cluster instance with publicly_accessible = true

## Why it likely fired

RDS instance with publicly_accessible = true

Aurora cluster instance with publicly_accessible = true

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-RDS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `publicly_accessible = false` on every `aws_db_instance`. A publicly
accessible RDS instance receives a DNS hostname resolvable from the
internet, exposing the database port to potential brute-force and
exploitation. Place the instance in private subnets and access it via a
bastion host, AWS Systems Manager Session Manager, or a VPC-peered
connection instead.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_db_instance" "example" {
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
}
```

_Enabling deletion protection is an in-place RDS modification; no replacement or downtime is required._

## Verification

Run `aws rds describe-db-instances --db-instance-identifier <id>` and
confirm `PubliclyAccessible` is `false`. Run `terraform plan` and verify
no diff shows `publicly_accessible = true`.

## References

**CIS Benchmark**
  - `CIS 2.3.3`

**Source**
  - [`catalog/SEC-AWS-RDS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-RDS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-RDS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-RDS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-RDS-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
