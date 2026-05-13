---
title: "SEC-AZURE-COSMOS-001 — Azure Cosmos DB account allows public network access"
description: "tf-analyze rule SEC-AZURE-COSMOS-001 (HIGH · security): Azure Cosmos DB account allows public network access"
keywords: "security, high, terraform, iac, azure, cis-5.4, mitre-T1190, mitre-T1530, cwe-284, d3-nta, nist-csf-pr.ac-3, nist-csf-pr.ac-5, nist-800-53-sc-7, nist-800-53-ac-3, csa-ccm-ivs-06"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-COSMOS-001 \u2014 Azure Cosmos DB account allows public network access",
  "description": "Set `public_network_access_enabled = false` and reach the account via a\nprivate endpoint. Add `is_virtual_network_filter_enabled = true` and\nenumerate `virtual_network_rule` blocks for the subnets that need\naccess, plus `ip_range_filter` fo",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-COSMOS-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-COSMOS-001/"
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
  "keywords": "security, high, terraform, CIS 5.4, MITRE T1190, MITRE T1530, CWE-284, D3-NTA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AZURE-COSMOS-001 — Azure Cosmos DB account allows public network access

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-COSMOS-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-COSMOS-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-COSMOS-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure Cosmos DB account allows public network access.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `azurerm_cosmosdb_account` (`public_network_access_enabled`) matching `/^true$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `azurerm_cosmosdb_account` has `public_network_access_enabled = true`,
exposing the Cosmos endpoint to the public internet. Even with
strong authentication, public exposure widens the attack surface
(credential stuffing, key leaks, network-layer scanning).

## Why it likely fired

`azurerm_cosmosdb_account` has `public_network_access_enabled = true`,
exposing the Cosmos endpoint to the public internet. Even with
strong authentication, public exposure widens the attack surface
(credential stuffing, key leaks, network-layer scanning).

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-COSMOS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `public_network_access_enabled = false` and reach the account via a
private endpoint. Add `is_virtual_network_filter_enabled = true` and
enumerate `virtual_network_rule` blocks for the subnets that need
access, plus `ip_range_filter` for any required allow-listed IPs.

    resource "azurerm_cosmosdb_account" "main" {
      # ...
      public_network_access_enabled    = false
      is_virtual_network_filter_enabled = true
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_cosmosdb_account" "example" {
  name                          = "example"
  location                      = azurerm_resource_group.example.location
  resource_group_name           = azurerm_resource_group.example.name
  offer_type                    = "Standard"
  kind                          = "GlobalDocumentDB"
  public_network_access_enabled = false
  consistency_policy { consistency_level = "Session" }
  geo_location {
    location          = azurerm_resource_group.example.location
    failover_priority = 0
  }
}
```

_Disabling public access breaks clients reaching the account over the public endpoint; ensure private endpoints are in place first._

## Verification

```sh
`az cosmosdb show --name <name> --resource-group <rg> \
  --query publicNetworkAccess` must return `"Disabled"`.
```

## References

**CIS Benchmark**
  - `CIS 5.4`

**PCI-DSS**
  - `Req-1.3`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**MITRE ATT&CK**
  - [`T1190`](https://attack.mitre.org/techniques/T1190/)
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)

**CWE**
  - [`CWE-284`](https://cwe.mitre.org/data/definitions/284.html)

**MITRE D3FEND**
  - [`D3-NTA`](https://d3fend.mitre.org/technique/D3-NTA/)

**NIST CSF 2.0**
  - [`PR.AC-3`](https://www.nist.gov/cyberframework)
  - [`PR.AC-5`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-7`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-7)
  - [`AC-3`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-3)

**CSA CCM v4**
  - [`IVS-06`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AZURE-COSMOS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-COSMOS-001.yaml) — canonical YAML

## Family

See also rules in the `SEC-AZURE-COSMOS-*` family:

- [`SEC-AZURE-COSMOS-002`](./SEC-AZURE-COSMOS-002.md) — Azure Cosmos DB account not using customer-managed key

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-COSMOS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-COSMOS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-COSMOS-001
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
