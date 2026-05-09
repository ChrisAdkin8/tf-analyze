# ⚠️ STK-AZURE-SQL-TDE-001 — Azure SQL Database missing transparent data encryption resource

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Azure SQL Database missing transparent data encryption resource.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_absent`** on `azurerm_mssql_database_transparent_data_encryption` — _the corpus is missing a resource type we expected to find given other resources present._
  `azurerm_mssql_database` present but no
`azurerm_mssql_database_transparent_data_encryption` resource in
the repository. TDE encrypts data files, log files, and backups at
rest. Without an explicit TDE resource, encryption state depends on
provider defaults and cannot be audited or enforced in code.

## Why it likely fired

`azurerm_mssql_database` present but no
`azurerm_mssql_database_transparent_data_encryption` resource in
the repository. TDE encrypts data files, log files, and backups at
rest. Without an explicit TDE resource, encryption state depends on
provider defaults and cannot be audited or enforced in code.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-SQL-TDE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a TDE resource for every SQL database and pin it to `"Enabled"`:

    resource "azurerm_mssql_database_transparent_data_encryption" "app" {
      database_id = azurerm_mssql_database.app.id
      state       = "Enabled"
    }

For databases on SQL Managed Instance (not SQL Server), TDE is enabled
by default and managed at the instance level — this rule applies only
to `azurerm_mssql_database` on `azurerm_mssql_server`.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_mssql_database_transparent_data_encryption" "example" {
  database_id = azurerm_mssql_database.example.id
  state       = "Enabled"
}
```

## Verification

```sh
`az sql db tde show --database <db> --server <server> \
  --resource-group <rg> --query 'status'`
must return `"Enabled"`.
```

## References

**CIS Benchmark**
  - `CIS 4.1.1`

**Source**
  - [`catalog/STK-AZURE-SQL-TDE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-SQL-TDE-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-SQL-TDE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-SQL-TDE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-SQL-TDE-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
