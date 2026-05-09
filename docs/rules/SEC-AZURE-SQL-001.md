# ⚠️ SEC-AZURE-SQL-001 — Azure SQL Server has no Azure AD administrator configured

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Azure SQL Server has no Azure AD administrator configured.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`resource_absent`** on `azurerm_mssql_server_azure_ad_administrator` — _the corpus is missing a resource type we expected to find given other resources present._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-SQL-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add an `azurerm_mssql_server_azure_ad_administrator` resource. Without Azure
AD auth, the server relies on SQL authentication (username/password) which is
harder to audit and enforce MFA on.

    resource "azurerm_mssql_server_azure_ad_administrator" "example" {
      server_id           = azurerm_mssql_server.example.id
      login               = "sqladmin"
      object_id           = var.aad_admin_object_id
      tenant_id           = data.azurerm_client_config.current.tenant_id
      azuread_authentication_only = true
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_mssql_server_azure_ad_administrator" "example" {
  server_id                   = azurerm_mssql_server.example.id
  login                       = "sqladmin"
  object_id                   = var.aad_admin_object_id
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  azuread_authentication_only = true
}
```

## Verification

After applying, confirm with:

    az sql server ad-admin list --server <name> --resource-group <rg>

The command should return a non-empty list.

## References

**CIS Benchmark**
  - `CIS 4.1.2`

**MITRE ATT&CK**
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)

**Source**
  - [`catalog/SEC-AZURE-SQL-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-SQL-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-SQL-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-SQL-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-SQL-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
