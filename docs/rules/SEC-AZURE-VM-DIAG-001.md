---
title: "SEC-AZURE-VM-DIAG-001 — Azure virtual machine missing boot diagnostics"
description: "tf-analyze rule SEC-AZURE-VM-DIAG-001 (MEDIUM · security): Azure virtual machine missing boot diagnostics"
keywords: "security, medium, terraform, iac, azure, mitre-T1562.008, cwe-778, d3-iaa, nist-csf-de.cm-1, nist-800-53-au-2"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-VM-DIAG-001 \u2014 Azure virtual machine missing boot diagnostics",
  "description": "Enable boot diagnostics on every VM:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-VM-DIAG-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-VM-DIAG-001/"
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
  "keywords": "security, medium, terraform, MITRE T1562.008, CWE-778, D3-IAA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-AZURE-VM-DIAG-001 — Azure virtual machine missing boot diagnostics

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-VM-DIAG-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-VM-DIAG-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-VM-DIAG-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure virtual machine missing boot diagnostics.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_linux_virtual_machine` (`boot_diagnostics`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_linux_virtual_machine` has no `boot_diagnostics` block.
Without serial console output captured to a storage account, a
boot failure or kernel panic cannot be diagnosed remotely — the
VM has to be torn down and recreated.
2. **`resource_missing_arg`** on `azurerm_windows_virtual_machine` (`boot_diagnostics`) — _the resource is missing a required attribute (or nested attribute path)._
  Windows VM missing boot_diagnostics

## Why it likely fired

`azurerm_linux_virtual_machine` has no `boot_diagnostics` block.
Without serial console output captured to a storage account, a
boot failure or kernel panic cannot be diagnosed remotely — the
VM has to be torn down and recreated.

Windows VM missing boot_diagnostics

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-VM-DIAG-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable boot diagnostics on every VM:

    resource "azurerm_linux_virtual_machine" "main" {
      # ...
      boot_diagnostics {}   # managed storage (no storage_account_uri = use platform-managed)
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_linux_virtual_machine" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_D2s_v3"
  admin_username      = "azureuser"
  network_interface_ids = [azurerm_network_interface.example.id]
  boot_diagnostics {}
  os_disk { caching = "ReadWrite" storage_account_type = "Standard_LRS" }
  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
}
```

## Verification

```sh
`az vm boot-diagnostics get-boot-log -g <rg> -n <name>` must return
serial output (not "boot diagnostics is not enabled").
```

## References

**SOC 2 Trust Services Criteria**
  - `CC7.2`

**MITRE ATT&CK**
  - [`T1562.008`](https://attack.mitre.org/techniques/T1562/008/)

**CWE**
  - [`CWE-778`](https://cwe.mitre.org/data/definitions/778.html)

**MITRE D3FEND**
  - [`D3-IAA`](https://d3fend.mitre.org/technique/D3-IAA/)

**NIST CSF 2.0**
  - [`DE.CM-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AU-2`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=au-2)

**Source**
  - [`catalog/SEC-AZURE-VM-DIAG-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-VM-DIAG-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-VM-DIAG-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-VM-DIAG-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-VM-DIAG-001
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
