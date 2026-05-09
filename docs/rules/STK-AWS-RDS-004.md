# ⚠️ STK-AWS-RDS-004 — RDS instance uses end-of-life database engine version

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **RDS instance uses end-of-life database engine version.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `aws_db_instance` (`engine_version`) matching `/^(5\.6|9\.6|10\.|11\.|12\.)/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  RDS instance using MySQL 5.6, PostgreSQL 9.6, 10, 11, or 12 — all
past or approaching end of standard support. AWS stops publishing
security patches for EOL versions; known CVEs accumulate silently.

## Why it likely fired

RDS instance using MySQL 5.6, PostgreSQL 9.6, 10, 11, or 12 — all
past or approaching end of standard support. AWS stops publishing
security patches for EOL versions; known CVEs accumulate silently.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AWS-RDS-004` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Upgrade to a supported engine version. AWS maintains a support calendar
at https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/MySQL.Concepts.VersionMgmt.html

Common upgrades:
- MySQL 5.6 → MySQL 8.0 (major version upgrade, test thoroughly)
- PostgreSQL 9.6 → PostgreSQL 16 (multiple hops: 9.6→11→14→16)
- PostgreSQL 10/11/12 → PostgreSQL 16

Use `aws rds describe-db-engine-versions` to enumerate supported
versions for your region and instance class.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_db_instance" "example" {
  engine         = "postgres"
  engine_version = "16.2"
  instance_class = "db.t3.medium"
  username       = "admin"
  password       = var.db_password
}
```

## Verification

```sh
`aws rds describe-db-instances --db-instance-identifier <id> \
  --query 'DBInstances[0].EngineVersion'`
must return a currently supported version string.
```

## References

**Source**
  - [`catalog/STK-AWS-RDS-004.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AWS-RDS-004.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AWS-RDS-004    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AWS-RDS-004` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AWS-RDS-004
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
