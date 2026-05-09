# ⚠️ STK-GCP-CLOUDSQL-005 — Cloud SQL instance uses end-of-life database version

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Cloud SQL instance uses end-of-life database version.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `google_sql_database_instance` (`database_version`) matching `/^(POSTGRES_9_6|MYSQL_5_6|MYSQL_5_7|SQLSERVER_2012|SQLSERVER_2014)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `database_version` set to a version that has reached end-of-life and
no longer receives security patches from the upstream project or Google.

## Why it likely fired

`database_version` set to a version that has reached end-of-life and
no longer receives security patches from the upstream project or Google.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-CLOUDSQL-005` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Upgrade to a supported version. Current Google Cloud SQL supported versions:
- PostgreSQL: 14, 15, 16
- MySQL: 8.0, 8.4
- SQL Server: 2017, 2019, 2022

Test the upgrade on a clone first:
    resource "google_sql_database_instance" "clone" {
      database_version = "POSTGRES_15"
      clone { source_instance_name = google_sql_database_instance.main.name }
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "google_sql_database_instance" "example" {
  name             = "example"
  database_version = "POSTGRES_16"
  settings {
    tier = "db-f1-micro"
  }
}
```

## Verification

```sh
`gcloud sql instances describe <name> --format='value(databaseVersion)'`
must return a supported, non-EOL version string.
```

## References

**Source**
  - [`catalog/STK-GCP-CLOUDSQL-005.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-CLOUDSQL-005.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-CLOUDSQL-005    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-CLOUDSQL-005` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-CLOUDSQL-005
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
