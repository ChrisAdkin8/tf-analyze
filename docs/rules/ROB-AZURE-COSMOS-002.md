---
title: "ROB-AZURE-COSMOS-002 — Azure Cosmos DB automatic failover disabled"
description: "tf-analyze rule ROB-AZURE-COSMOS-002 (MEDIUM · robustness): Azure Cosmos DB automatic failover disabled"
keywords: "robustness, medium, terraform, iac, azure, mitre-T1485, nist-csf-pr.ip-4, nist-800-53-cp-10"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-AZURE-COSMOS-002 \u2014 Azure Cosmos DB automatic failover disabled",
  "description": "Enable automatic failover on multi-region Cosmos accounts:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-AZURE-COSMOS-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-AZURE-COSMOS-002/"
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
  "keywords": "robustness, medium, terraform, MITRE T1485",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# 💡 ROB-AZURE-COSMOS-002 — Azure Cosmos DB automatic failover disabled

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-AZURE-COSMOS-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-AZURE-COSMOS-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-AZURE-COSMOS-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure Cosmos DB automatic failover disabled.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `azurerm_cosmosdb_account` (`automatic_failover_enabled`) matching `/^false$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `azurerm_cosmosdb_account.automatic_failover_enabled = false`.
A regional outage requires manual operator intervention to
failover — RTO is bounded by oncall response time, not Cosmos
capability.
2. **`resource_missing_arg`** on `azurerm_cosmosdb_account` (`automatic_failover_enabled`) — _the resource is missing a required attribute (or nested attribute path)._
  Multi-region Cosmos account without `automatic_failover_enabled`
(defaults to false in some provider versions).

## Why it likely fired

`azurerm_cosmosdb_account.automatic_failover_enabled = false`.
A regional outage requires manual operator intervention to
failover — RTO is bounded by oncall response time, not Cosmos
capability.

Multi-region Cosmos account without `automatic_failover_enabled`
(defaults to false in some provider versions).

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-AZURE-COSMOS-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable automatic failover on multi-region Cosmos accounts:

    resource "azurerm_cosmosdb_account" "main" {
      # ...
      automatic_failover_enabled = true
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_cosmosdb_account" "example" {
  name                       = "example"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  offer_type                 = "Standard"
  kind                       = "GlobalDocumentDB"
  automatic_failover_enabled = true
  consistency_policy { consistency_level = "Session" }
  geo_location {
    location          = azurerm_resource_group.example.location
    failover_priority = 0
  }
  geo_location {
    location          = "westus2"
    failover_priority = 1
  }
}
```

## Verification

```sh
`az cosmosdb show -g <rg> -n <name> --query 'enableAutomaticFailover'`
must return `true`.
```

## References

**MITRE ATT&CK**
  - [`T1485`](https://attack.mitre.org/techniques/T1485/)

**NIST CSF 2.0**
  - [`PR.IP-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`CP-10`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=cp-10)

**Source**
  - [`catalog/ROB-AZURE-COSMOS-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-AZURE-COSMOS-002.yaml) — canonical YAML

## Family

See also rules in the `ROB-AZURE-COSMOS-*` family:

- [`ROB-AZURE-COSMOS-001`](./ROB-AZURE-COSMOS-001.md) — Azure Cosmos DB backup policy not Continuous

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-AZURE-COSMOS-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-AZURE-COSMOS-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-AZURE-COSMOS-002
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
