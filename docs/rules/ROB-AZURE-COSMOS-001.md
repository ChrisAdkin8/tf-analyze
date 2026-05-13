---
title: "ROB-AZURE-COSMOS-001 — Azure Cosmos DB backup policy not Continuous"
description: "tf-analyze rule ROB-AZURE-COSMOS-001 (MEDIUM · robustness): Azure Cosmos DB backup policy not Continuous"
keywords: "robustness, medium, terraform, iac, azure, mitre-T1485, mitre-T1490, cwe-779, nist-csf-pr.ip-4, nist-800-53-cp-9, csa-ccm-bcr-08"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-AZURE-COSMOS-001 \u2014 Azure Cosmos DB backup policy not Continuous",
  "description": "Switch backup type to Continuous (note: Continuous backup forces\nrecreation if Periodic was set at creation):",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-AZURE-COSMOS-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-AZURE-COSMOS-001/"
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
  "keywords": "robustness, medium, terraform, MITRE T1485, MITRE T1490, CWE-779",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# 💡 ROB-AZURE-COSMOS-001 — Azure Cosmos DB backup policy not Continuous

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-AZURE-COSMOS-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-AZURE-COSMOS-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-AZURE-COSMOS-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure Cosmos DB backup policy not Continuous.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_body_contains`** on `azurerm_cosmosdb_account` matching `/backup\s*\{[^}]*type\s*=\s*"Periodic"/` — _the resource body matches a regex inside the block._
  `azurerm_cosmosdb_account.backup.type = "Periodic"` provides only
24-48h granularity. Continuous backup with PITR gives 7- or 30-day
restore window at any point in time — required for high-RPO
workloads.

## Why it likely fired

`azurerm_cosmosdb_account.backup.type = "Periodic"` provides only
24-48h granularity. Continuous backup with PITR gives 7- or 30-day
restore window at any point in time — required for high-RPO
workloads.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-AZURE-COSMOS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Switch backup type to Continuous (note: Continuous backup forces
recreation if Periodic was set at creation):

    resource "azurerm_cosmosdb_account" "main" {
      # ...
      backup {
        type = "Continuous"
        tier = "Continuous30Days"
      }
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "azurerm_cosmosdb_account" "example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"
  backup {
    type = "Continuous"
    tier = "Continuous30Days"
  }
  consistency_policy { consistency_level = "Session" }
  geo_location {
    location          = azurerm_resource_group.example.location
    failover_priority = 0
  }
}
```

## Verification

```sh
`az cosmosdb show -g <rg> -n <name> --query 'backupPolicy.type'` must
return `Continuous`.
```

## References

**PCI-DSS**
  - `Req-3.1`

**SOC 2 Trust Services Criteria**
  - `A1.2`

**MITRE ATT&CK**
  - [`T1485`](https://attack.mitre.org/techniques/T1485/)
  - [`T1490`](https://attack.mitre.org/techniques/T1490/)

**CWE**
  - [`CWE-779`](https://cwe.mitre.org/data/definitions/779.html)

**NIST CSF 2.0**
  - [`PR.IP-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`CP-9`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=cp-9)

**CSA CCM v4**
  - [`BCR-08`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/ROB-AZURE-COSMOS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-AZURE-COSMOS-001.yaml) — canonical YAML

## Family

See also rules in the `ROB-AZURE-COSMOS-*` family:

- [`ROB-AZURE-COSMOS-002`](./ROB-AZURE-COSMOS-002.md) — Azure Cosmos DB automatic failover disabled

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-AZURE-COSMOS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-AZURE-COSMOS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-AZURE-COSMOS-001
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
