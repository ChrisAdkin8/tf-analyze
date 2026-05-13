---
title: "SEC-AZURE-VMSS-IDENT-001 — Azure VM Scale Set has no managed identity"
description: "tf-analyze rule SEC-AZURE-VMSS-IDENT-001 (MEDIUM · security): Azure VM Scale Set has no managed identity"
keywords: "security, medium, terraform, iac, azure, cis-1.4, mitre-T1552.001, cwe-798, d3-cr, nist-csf-pr.ac-1, nist-800-53-ia-5"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-VMSS-IDENT-001 \u2014 Azure VM Scale Set has no managed identity",
  "description": "Bind a system-assigned managed identity so workloads can use the\nAzure Instance Metadata Service to obtain short-lived tokens:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-VMSS-IDENT-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-VMSS-IDENT-001/"
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
  "keywords": "security, medium, terraform, CIS 1.4, MITRE T1552.001, CWE-798, D3-CR",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-AZURE-VMSS-IDENT-001 — Azure VM Scale Set has no managed identity

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-VMSS-IDENT-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-VMSS-IDENT-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-VMSS-IDENT-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure VM Scale Set has no managed identity.** This rule has `default_urgency: MEDIUM` and operates on a module blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_linux_virtual_machine_scale_set` (`identity`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_linux_virtual_machine_scale_set` has no `identity` block.
Workloads on the scale set authenticate to Azure services with
static credentials baked into custom_data / app config — the
classic credential-leak class.
2. **`resource_missing_arg`** on `azurerm_windows_virtual_machine_scale_set` (`identity`) — _the resource is missing a required attribute (or nested attribute path)._
  Windows VMSS missing managed identity

## Why it likely fired

`azurerm_linux_virtual_machine_scale_set` has no `identity` block.
Workloads on the scale set authenticate to Azure services with
static credentials baked into custom_data / app config — the
classic credential-leak class.

Windows VMSS missing managed identity

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-VMSS-IDENT-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Bind a system-assigned managed identity so workloads can use the
Azure Instance Metadata Service to obtain short-lived tokens:

    resource "azurerm_linux_virtual_machine_scale_set" "main" {
      # ...
      identity { type = "SystemAssigned" }
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_linux_virtual_machine_scale_set" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Standard_D2s_v3"
  instances           = 3
  admin_username      = "azureuser"
  identity { type = "SystemAssigned" }
  os_disk { caching = "ReadWrite" storage_account_type = "Standard_LRS" }
  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
  network_interface {
    name    = "ni"
    primary = true
    ip_configuration {
      name      = "ic"
      primary   = true
      subnet_id = azurerm_subnet.example.id
    }
  }
}
```

## Verification

```sh
`az vmss show -g <rg> -n <name> --query 'identity.type'` must return
`SystemAssigned` (or `UserAssigned`).
```

## References

**CIS Benchmark**
  - `CIS 1.4`

**PCI-DSS**
  - `Req-3.6`

**SOC 2 Trust Services Criteria**
  - `CC6.3`

**MITRE ATT&CK**
  - [`T1552.001`](https://attack.mitre.org/techniques/T1552/001/)

**CWE**
  - [`CWE-798`](https://cwe.mitre.org/data/definitions/798.html)

**MITRE D3FEND**
  - [`D3-CR`](https://d3fend.mitre.org/technique/D3-CR/)

**NIST CSF 2.0**
  - [`PR.AC-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`IA-5`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ia-5)

**Source**
  - [`catalog/SEC-AZURE-VMSS-IDENT-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-VMSS-IDENT-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-VMSS-IDENT-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-VMSS-IDENT-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-VMSS-IDENT-001
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
