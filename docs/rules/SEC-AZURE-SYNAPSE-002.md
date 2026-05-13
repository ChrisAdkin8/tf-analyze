---
title: "SEC-AZURE-SYNAPSE-002 — Azure Synapse workspace missing data exfiltration protection"
description: "tf-analyze rule SEC-AZURE-SYNAPSE-002 (HIGH · security): Azure Synapse workspace missing data exfiltration protection"
keywords: "security, high, terraform, iac, azure, mitre-T1567, cwe-200, d3-nta, nist-csf-pr.ds-5, nist-800-53-sc-7"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-SYNAPSE-002 \u2014 Azure Synapse workspace missing data exfiltration protection",
  "description": "Enable exfiltration protection (requires Managed VNet):",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-SYNAPSE-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-SYNAPSE-002/"
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
  "keywords": "security, high, terraform, MITRE T1567, CWE-200, D3-NTA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AZURE-SYNAPSE-002 — Azure Synapse workspace missing data exfiltration protection

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-SYNAPSE-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-SYNAPSE-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-SYNAPSE-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure Synapse workspace missing data exfiltration protection.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_synapse_workspace` (`data_exfiltration_protection_enabled`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_synapse_workspace.data_exfiltration_protection_enabled`
is not set to `true`. Notebook authors and pipeline operators
can `COPY INTO` external storage accounts — data egresses
Synapse without VNet controls.

## Why it likely fired

`azurerm_synapse_workspace.data_exfiltration_protection_enabled`
is not set to `true`. Notebook authors and pipeline operators
can `COPY INTO` external storage accounts — data egresses
Synapse without VNet controls.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-SYNAPSE-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable exfiltration protection (requires Managed VNet):

    resource "azurerm_synapse_workspace" "main" {
      # ...
      managed_virtual_network_enabled      = true
      data_exfiltration_protection_enabled = true
    }

This blocks outbound traffic to non-approved storage accounts and
to any data source not behind an approved managed private endpoint.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "azurerm_synapse_workspace" "example" {
  name                                 = "example"
  resource_group_name                  = azurerm_resource_group.example.name
  location                             = azurerm_resource_group.example.location
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.example.id
  sql_administrator_login              = "synapseadmin"
  sql_administrator_login_password     = "REDACTED"
  public_network_access_enabled        = false
  managed_virtual_network_enabled      = true
  data_exfiltration_protection_enabled = true
  identity { type = "SystemAssigned" }
}
```

## Verification

```sh
`az synapse workspace show -g <rg> -n <name> --query 'workspaceProperties.dataExfiltrationProtection'`
must return enabled.
```

## References

**PCI-DSS**
  - `Req-1.3`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**MITRE ATT&CK**
  - [`T1567`](https://attack.mitre.org/techniques/T1567/)

**CWE**
  - [`CWE-200`](https://cwe.mitre.org/data/definitions/200.html)

**MITRE D3FEND**
  - [`D3-NTA`](https://d3fend.mitre.org/technique/D3-NTA/)

**NIST CSF 2.0**
  - [`PR.DS-5`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-7`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-7)

**Source**
  - [`catalog/SEC-AZURE-SYNAPSE-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-SYNAPSE-002.yaml) — canonical YAML

## Family

See also rules in the `SEC-AZURE-SYNAPSE-*` family:

- [`SEC-AZURE-SYNAPSE-001`](./SEC-AZURE-SYNAPSE-001.md) — Azure Synapse workspace permits public network access

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-SYNAPSE-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-SYNAPSE-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-SYNAPSE-002
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
