# ⚠️ STK-AZURE-SQL-001 — Azure MySQL/PostgreSQL single server is deprecated

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Azure MySQL/PostgreSQL single server is deprecated.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_present`** on `azurerm_mysql_server` — _this resource type exists in the corpus and is itself a finding._
  `azurerm_mysql_server` (Azure Database for MySQL — Single Server)
is deprecated. Microsoft ended support for the Single Server SKU on
September 16, 2024. Deprecated servers no longer receive security
patches. Migrate to `azurerm_mysql_flexible_server`.
2. **`resource_present`** on `azurerm_postgresql_server` — _this resource type exists in the corpus and is itself a finding._
  `azurerm_postgresql_server` (Azure Database for PostgreSQL — Single
Server) is retired. Microsoft ended support for Single Server on
March 28, 2025. Migrate to `azurerm_postgresql_flexible_server`.

## Why it likely fired

`azurerm_mysql_server` (Azure Database for MySQL — Single Server)
is deprecated. Microsoft ended support for the Single Server SKU on
September 16, 2024. Deprecated servers no longer receive security
patches. Migrate to `azurerm_mysql_flexible_server`.

`azurerm_postgresql_server` (Azure Database for PostgreSQL — Single
Server) is retired. Microsoft ended support for Single Server on
March 28, 2025. Migrate to `azurerm_postgresql_flexible_server`.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-SQL-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Migrate to the Flexible Server SKU:

    # MySQL
    resource "azurerm_mysql_flexible_server" "app" {
      name                   = "mysql-app"
      resource_group_name    = azurerm_resource_group.app.name
      location               = azurerm_resource_group.app.location
      administrator_login    = "mysqladmin"
      administrator_password = var.mysql_password
      backup_retention_days  = 7
      sku_name               = "B_Standard_B1ms"
      version                = "8.0.21"
    }

    # PostgreSQL
    resource "azurerm_postgresql_flexible_server" "app" {
      name                   = "psql-app"
      resource_group_name    = azurerm_resource_group.app.name
      location               = azurerm_resource_group.app.location
      administrator_login    = "psqladmin"
      administrator_password = var.psql_password
      sku_name               = "B_Standard_B1ms"
      version                = "16"
    }

Equivalent to GCP `STK-GCP-CLOUDSQL-005` (EOL engine version).

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "azurerm_mysql_flexible_server" "example" {
  name                   = "example"
  resource_group_name    = azurerm_resource_group.example.name
  location               = azurerm_resource_group.example.location
  administrator_login    = "adminuser"
  administrator_password = var.db_password
  sku_name               = "GP_Standard_D2ds_v4"
  version                = "8.0.21"
}
```

## Verification

Confirm no `azurerm_mysql_server` or `azurerm_postgresql_server` resources
remain in any Terraform state file. Check the Azure Portal: "Azure Database
for MySQL — Single Server" and "Azure Database for PostgreSQL — Single
Server" should show no instances.

## References

**Source**
  - [`catalog/STK-AZURE-SQL-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-SQL-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-SQL-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-SQL-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-SQL-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
