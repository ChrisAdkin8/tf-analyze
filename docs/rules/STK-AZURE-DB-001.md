---
title: "STK-AZURE-DB-001 — Azure MySQL/PostgreSQL server missing SSL enforcement"
description: "tf-analyze rule STK-AZURE-DB-001 (HIGH · stack): Azure MySQL/PostgreSQL server missing SSL enforcement"
keywords: "stack, high, terraform, iac, azure, cis-4.3.1"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AZURE-DB-001 \u2014 Azure MySQL/PostgreSQL server missing SSL enforcement",
  "description": "Set `ssl_enforcement_enabled = true` on every MySQL and PostgreSQL\nSingle Server resource:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-DB-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-DB-001/"
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
  "keywords": "stack, high, terraform, CIS 4.3.1",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-AZURE-DB-001 — Azure MySQL/PostgreSQL server missing SSL enforcement

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AZURE-DB-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-AZURE-DB-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-AZURE-DB-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure MySQL/PostgreSQL server missing SSL enforcement.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_mysql_server` (`ssl_enforcement_enabled`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_mysql_server` without `ssl_enforcement_enabled`. Client
connections can be made over plaintext, exposing credentials and
query results on the network.
2. **`hcl_attr`** on `azurerm_mysql_server` (`ssl_enforcement_enabled`) not equal to `True` — _an attribute value differs from the expected literal._
3. **`resource_missing_arg`** on `azurerm_postgresql_server` (`ssl_enforcement_enabled`) — _the resource is missing a required attribute (or nested attribute path)._
4. **`hcl_attr`** on `azurerm_postgresql_server` (`ssl_enforcement_enabled`) not equal to `True` — _an attribute value differs from the expected literal._

## Why it likely fired

`azurerm_mysql_server` without `ssl_enforcement_enabled`. Client
connections can be made over plaintext, exposing credentials and
query results on the network.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-DB-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `ssl_enforcement_enabled = true` on every MySQL and PostgreSQL
Single Server resource:

    resource "azurerm_mysql_server" "app" {
      ssl_enforcement_enabled          = true
      ssl_minimal_tls_version_enforced = "TLS1_2"
      # ...
    }

For Flexible Server (the preferred, non-deprecated resource), SSL is
enforced by default and controlled via `azurerm_mysql_flexible_server_configuration`
with the `require_secure_transport` parameter.

Equivalent to GCP `STK-GCP-CLOUDSQL-004` (require_ssl).

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_mysql_server" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku_name            = "B_Gen5_1"
  ssl_enforcement_enabled          = true
  ssl_minimal_tls_version_enforced = "TLS1_2"
}
```

## Verification

```sh
`az mysql server show --name <server> --resource-group <rg> \
  --query 'sslEnforcement'`
must return `"Enabled"`.
```

## References

**CIS Benchmark**
  - `CIS 4.3.1`

**Source**
  - [`catalog/STK-AZURE-DB-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-DB-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-DB-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-DB-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-DB-001
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
