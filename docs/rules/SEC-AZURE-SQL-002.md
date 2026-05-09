---
title: "SEC-AZURE-SQL-002 — Azure SQL Server firewall rule allows access from all IPs"
description: "tf-analyze rule SEC-AZURE-SQL-002 (HIGH · security): Azure SQL Server firewall rule allows access from all IPs"
keywords: "security, high, terraform, iac, azure, cis-4.1.3"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-SQL-002 \u2014 Azure SQL Server firewall rule allows access from all IPs",
  "description": "Replace world-open firewall rules with the narrowest CIDR your workload\nneeds. Prefer Private Endpoints over firewall rules for production:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-SQL-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-SQL-002/"
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
  "keywords": "security, high, terraform, CIS 4.1.3",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AZURE-SQL-002 — Azure SQL Server firewall rule allows access from all IPs

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-SQL-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure SQL Server firewall rule allows access from all IPs.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `azurerm_mssql_firewall_rule` (`start_ip_address`) matching `/^0\.0\.0\.0$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `azurerm_mssql_firewall_rule` with `start_ip_address = "0.0.0.0"`.
This is the Azure convention for "Allow Azure services and resources
to access this server" — but it also opens the SQL endpoint to any
Azure-hosted attacker (a shared IP range). Combined with weak
credentials, it becomes internet-exposed.
2. **`resource_arg`** on `azurerm_mssql_firewall_rule` (`end_ip_address`) matching `/^255\.255\.255\.255$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `azurerm_mssql_firewall_rule` with `end_ip_address = "255.255.255.255"`
— a world-open rule accepting connections from every IP address.

## Why it likely fired

`azurerm_mssql_firewall_rule` with `start_ip_address = "0.0.0.0"`.
This is the Azure convention for "Allow Azure services and resources
to access this server" — but it also opens the SQL endpoint to any
Azure-hosted attacker (a shared IP range). Combined with weak
credentials, it becomes internet-exposed.

`azurerm_mssql_firewall_rule` with `end_ip_address = "255.255.255.255"`
— a world-open rule accepting connections from every IP address.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-SQL-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace world-open firewall rules with the narrowest CIDR your workload
needs. Prefer Private Endpoints over firewall rules for production:

    # Preferred: Private Endpoint (no public network access)
    resource "azurerm_mssql_server" "app" {
      public_network_access_enabled = false
    }

    resource "azurerm_private_endpoint" "sql" {
      # ... connect the SQL server to a private VNet subnet
    }

    # If public access is required, use minimum CIDR:
    resource "azurerm_mssql_firewall_rule" "app_ci" {
      server_id        = azurerm_mssql_server.app.id
      name             = "ci-runner"
      start_ip_address = "203.0.113.10"
      end_ip_address   = "203.0.113.10"
    }

Equivalent to GCP `SEC-GCP-SQL-PUBLIC-001` (Cloud SQL authorizing
all networks via `ipv4_enabled = true`).

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_mssql_firewall_rule" "example" {
  name             = "allow-specific-ip"
  server_id        = azurerm_mssql_server.example.id
  start_ip_address = "203.0.113.10"
  end_ip_address   = "203.0.113.10"
}
```

## Verification

```sh
`az sql server firewall-rule list --server <server> --resource-group <rg>`
must show no rules with `startIpAddress = 0.0.0.0` or
`endIpAddress = 255.255.255.255`.
```

## References

**CIS Benchmark**
  - `CIS 4.1.3`

**Source**
  - [`catalog/SEC-AZURE-SQL-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-SQL-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-SQL-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-SQL-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-SQL-002
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
