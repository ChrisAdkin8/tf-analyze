# 💡 ROB-AZURE-SQL-001 — Azure SQL database missing short-term backup retention policy

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Azure SQL database missing short-term backup retention policy.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_mssql_database` (`short_term_retention_policy`) — _the resource is missing a required attribute (or nested attribute path)._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-AZURE-SQL-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add `short_term_retention_policy { retention_days = 35 }`. The default is
7 days — too short for post-incident recovery in production. 35 days covers
a typical monthly billing cycle.

    resource "azurerm_mssql_database" "example" {
      # ...
      short_term_retention_policy {
        retention_days           = 35
        backup_interval_in_hours = 12
      }
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_mssql_database" "example" {
  name      = "example"
  server_id = azurerm_mssql_server.example.id
  short_term_retention_policy {
    retention_days           = 35
    backup_interval_in_hours = 12
  }
}
```

## Verification

After applying, confirm with:

    az sql db str-policy show \
      --server <s> --database <db> --resource-group <rg> \
      --query retentionDays

The value should be >= 14 for non-prod and >= 35 for production.

## References

**CIS Benchmark**
  - `CIS 4.1.7`

**Source**
  - [`catalog/ROB-AZURE-SQL-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-AZURE-SQL-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-AZURE-SQL-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-AZURE-SQL-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-AZURE-SQL-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
