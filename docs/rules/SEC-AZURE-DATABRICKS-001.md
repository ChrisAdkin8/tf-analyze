---
title: "SEC-AZURE-DATABRICKS-001 — Azure Databricks workspace publicly accessible (no_public_ip = false)"
description: "tf-analyze rule SEC-AZURE-DATABRICKS-001 (HIGH · security): Azure Databricks workspace publicly accessible (no_public_ip = false)"
keywords: "security, high, terraform, iac, azure, cis-3.5, mitre-T1190, cwe-284, d3-nta, nist-csf-pr.ac-5, nist-800-53-sc-7"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-DATABRICKS-001 \u2014 Azure Databricks workspace publicly accessible (no_public_ip = false)",
  "description": "Provision the workspace with no_public_ip and disable public\nnetwork access:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-DATABRICKS-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-DATABRICKS-001/"
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
  "keywords": "security, high, terraform, CIS 3.5, MITRE T1190, CWE-284, D3-NTA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AZURE-DATABRICKS-001 — Azure Databricks workspace publicly accessible (no_public_ip = false)

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-DATABRICKS-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-DATABRICKS-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-DATABRICKS-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure Databricks workspace publicly accessible (no_public_ip = false).** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`resource_body_contains`** on `azurerm_databricks_workspace` matching `/no_public_ip\s*=\s*false/` — _the resource body matches a regex inside the block._
  `azurerm_databricks_workspace.custom_parameters.no_public_ip = false`
assigns Databricks worker nodes public IPs. The workspace control
plane is reachable from the public internet.
2. **`resource_arg`** on `azurerm_databricks_workspace` (`public_network_access_enabled`) matching `/^true$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Databricks workspace public_network_access_enabled = true

## Why it likely fired

`azurerm_databricks_workspace.custom_parameters.no_public_ip = false`
assigns Databricks worker nodes public IPs. The workspace control
plane is reachable from the public internet.

Databricks workspace public_network_access_enabled = true

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-DATABRICKS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Provision the workspace with no_public_ip and disable public
network access:

    resource "azurerm_databricks_workspace" "main" {
      # ...
      public_network_access_enabled = false
      custom_parameters {
        no_public_ip = true
        virtual_network_id = azurerm_virtual_network.main.id
        public_subnet_name = azurerm_subnet.public.name
        private_subnet_name = azurerm_subnet.private.name
      }
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "azurerm_databricks_workspace" "example" {
  name                          = "example"
  resource_group_name           = azurerm_resource_group.example.name
  location                      = azurerm_resource_group.example.location
  sku                           = "premium"
  public_network_access_enabled = false
  custom_parameters {
    no_public_ip        = true
    virtual_network_id  = azurerm_virtual_network.example.id
    public_subnet_name  = azurerm_subnet.public.name
    private_subnet_name = azurerm_subnet.private.name
  }
}
```

## Verification

```sh
`az databricks workspace show -g <rg> -n <name> --query 'publicNetworkAccess'`
must return `Disabled`.
```

## References

**CIS Benchmark**
  - `CIS 3.5`

**PCI-DSS**
  - `Req-1.3`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**MITRE ATT&CK**
  - [`T1190`](https://attack.mitre.org/techniques/T1190/)

**CWE**
  - [`CWE-284`](https://cwe.mitre.org/data/definitions/284.html)

**MITRE D3FEND**
  - [`D3-NTA`](https://d3fend.mitre.org/technique/D3-NTA/)

**NIST CSF 2.0**
  - [`PR.AC-5`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-7`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-7)

**Source**
  - [`catalog/SEC-AZURE-DATABRICKS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-DATABRICKS-001.yaml) — canonical YAML

## Family

See also rules in the `SEC-AZURE-DATABRICKS-*` family:

- [`SEC-AZURE-DATABRICKS-002`](./SEC-AZURE-DATABRICKS-002.md) — Azure Databricks workspace missing customer-managed key (DBFS)

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-DATABRICKS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-DATABRICKS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-DATABRICKS-001
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
