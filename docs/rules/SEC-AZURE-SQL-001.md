---
title: "SEC-AZURE-SQL-001 — Azure SQL Server has no Azure AD administrator configured"
description: "tf-analyze rule SEC-AZURE-SQL-001 (HIGH · security): Azure SQL Server has no Azure AD administrator configured"
keywords: "security, high, terraform, iac, azure, cis-4.1.2, mitre-T1530"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-SQL-001 \u2014 Azure SQL Server has no Azure AD administrator configured",
  "description": "Add an `azurerm_mssql_server_azure_ad_administrator` resource. Without Azure\nAD auth, the server relies on SQL authentication (username/password) which is\nharder to audit and enforce MFA on.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-SQL-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-SQL-001/"
  },
  "author": {
    "@type": "Organization",
    "name": "tf-analyze"
  },
  "publisher": {
    "@type": "Organization",
    "name": "tf-analyze",
    "url": "https://chrisadkin8.github.io/tf-analyze"
  },
  "keywords": "security, high, terraform, CIS 4.1.2, MITRE T1530",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AZURE-SQL-001 — Azure SQL Server has no Azure AD administrator configured

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-SQL-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

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
{% if site.giscus.enabled %}
---

## Discussion

<script src="https://giscus.app/client.js"
        data-repo="{{ site.giscus.repo }}"
        data-repo-id="{{ site.giscus.repo_id }}"
        data-category="{{ site.giscus.category }}"
        data-category-id="{{ site.giscus.category_id }}"
        data-mapping="{{ site.giscus.mapping }}"
        data-strict="0"
        data-reactions-enabled="{{ site.giscus.reactions }}"
        data-emit-metadata="{{ site.giscus.emit_metadata }}"
        data-input-position="{{ site.giscus.input_position }}"
        data-theme="{{ site.giscus.theme }}"
        data-lang="en"
        crossorigin="anonymous"
        async>
</script>

{% endif %}
