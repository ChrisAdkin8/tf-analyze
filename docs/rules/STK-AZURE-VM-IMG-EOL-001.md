---
title: "STK-AZURE-VM-IMG-EOL-001 — Azure virtual machine using end-of-life OS image"
description: "tf-analyze rule STK-AZURE-VM-IMG-EOL-001 (HIGH · stack): Azure virtual machine using end-of-life OS image"
keywords: "stack, high, terraform, iac, azure, mitre-T1195.002, cwe-1104, d3-sca, nist-csf-id.sc-2, nist-800-53-sr-4, slsa-deps"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AZURE-VM-IMG-EOL-001 \u2014 Azure virtual machine using end-of-life OS image",
  "description": "Upgrade to a supported image family. Current Azure-supported Linux\nLTS: Ubuntu 22.04 (Jammy), 24.04 (Noble), Debian 12, RHEL 9, SLES 15.\nWindows: Server 2019, 2022, 2025.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-VM-IMG-EOL-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-VM-IMG-EOL-001/"
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
  "keywords": "stack, high, terraform, MITRE T1195.002, CWE-1104, D3-SCA",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-AZURE-VM-IMG-EOL-001 — Azure virtual machine using end-of-life OS image

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AZURE-VM-IMG-EOL-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-AZURE-VM-IMG-EOL-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-AZURE-VM-IMG-EOL-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure virtual machine using end-of-life OS image.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_body_contains`** on `azurerm_linux_virtual_machine` matching `/offer\s*=\s*"(UbuntuServer|0001-com-ubuntu-server-(focal|bionic|xenial))"/` — _the resource body matches a regex inside the block._
  `azurerm_linux_virtual_machine.source_image_reference.offer`
points at an EOL Ubuntu LTS image (Bionic 18.04, Xenial 16.04,
or the deprecated `UbuntuServer` SKU family). Standard support
ended; only ESM tier (paid) receives security patches.
2. **`resource_body_contains`** on `azurerm_windows_virtual_machine` matching `/sku\s*=\s*"(2012-Datacenter|2016-Datacenter|2008-R2-SP1)"/` — _the resource body matches a regex inside the block._
  Windows Server 2008-R2 / 2012 / 2012-R2 are out of mainstream support

## Why it likely fired

`azurerm_linux_virtual_machine.source_image_reference.offer`
points at an EOL Ubuntu LTS image (Bionic 18.04, Xenial 16.04,
or the deprecated `UbuntuServer` SKU family). Standard support
ended; only ESM tier (paid) receives security patches.

Windows Server 2008-R2 / 2012 / 2012-R2 are out of mainstream support

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-VM-IMG-EOL-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Upgrade to a supported image family. Current Azure-supported Linux
LTS: Ubuntu 22.04 (Jammy), 24.04 (Noble), Debian 12, RHEL 9, SLES 15.
Windows: Server 2019, 2022, 2025.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "azurerm_linux_virtual_machine" "example" {
  name                  = "example"
  resource_group_name   = azurerm_resource_group.example.name
  location              = azurerm_resource_group.example.location
  size                  = "Standard_D2s_v3"
  admin_username        = "azureuser"
  network_interface_ids = [azurerm_network_interface.example.id]
  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
  os_disk { caching = "ReadWrite" storage_account_type = "Standard_LRS" }
}
```

## Verification

```sh
`az vm show -g <rg> -n <name> --query 'storageProfile.imageReference'`
must reference a currently-supported image SKU.
```

## References

**MITRE ATT&CK**
  - [`T1195.002`](https://attack.mitre.org/techniques/T1195/002/)

**CWE**
  - [`CWE-1104`](https://cwe.mitre.org/data/definitions/1104.html)

**MITRE D3FEND**
  - [`D3-SCA`](https://d3fend.mitre.org/technique/D3-SCA/)

**NIST CSF 2.0**
  - [`ID.SC-2`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SR-4`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sr-4)

**SLSA v1.0**
  - [`SLSA deps`](https://slsa.dev/spec/v1.0/deps-track)

**Source**
  - [`catalog/STK-AZURE-VM-IMG-EOL-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-VM-IMG-EOL-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-VM-IMG-EOL-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-VM-IMG-EOL-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-VM-IMG-EOL-001
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
