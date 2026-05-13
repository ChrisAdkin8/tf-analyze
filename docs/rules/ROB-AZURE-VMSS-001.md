---
title: "ROB-AZURE-VMSS-001 — Azure VM Scale Set missing automatic instance repair"
description: "tf-analyze rule ROB-AZURE-VMSS-001 (MEDIUM · robustness): Azure VM Scale Set missing automatic instance repair"
keywords: "robustness, medium, terraform, iac, azure, mitre-T1485, nist-csf-pr.ip-1, nist-800-53-cp-10"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-AZURE-VMSS-001 \u2014 Azure VM Scale Set missing automatic instance repair",
  "description": "Pair the scale set with a load-balancer or application-gateway\nhealth probe and enable automatic_instance_repair:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-AZURE-VMSS-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-AZURE-VMSS-001/"
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

# 💡 ROB-AZURE-VMSS-001 — Azure VM Scale Set missing automatic instance repair

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-AZURE-VMSS-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-AZURE-VMSS-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-AZURE-VMSS-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure VM Scale Set missing automatic instance repair.** This rule has `default_urgency: MEDIUM` and operates on a module blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_linux_virtual_machine_scale_set` (`automatic_instance_repair`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_linux_virtual_machine_scale_set` has no
`automatic_instance_repair` block. Unhealthy instances stay in
the scale set until manual intervention — capacity drops below
the requested target after a host failure.
2. **`resource_missing_arg`** on `azurerm_windows_virtual_machine_scale_set` (`automatic_instance_repair`) — _the resource is missing a required attribute (or nested attribute path)._
  Windows VMSS missing automatic_instance_repair

## Why it likely fired

`azurerm_linux_virtual_machine_scale_set` has no
`automatic_instance_repair` block. Unhealthy instances stay in
the scale set until manual intervention — capacity drops below
the requested target after a host failure.

Windows VMSS missing automatic_instance_repair

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-AZURE-VMSS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Pair the scale set with a load-balancer or application-gateway
health probe and enable automatic_instance_repair:

    resource "azurerm_linux_virtual_machine_scale_set" "main" {
      # ...
      health_probe_id = azurerm_lb_probe.main.id
      automatic_instance_repair {
        enabled      = true
        grace_period = "PT10M"
      }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_linux_virtual_machine_scale_set" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Standard_D2s_v3"
  instances           = 3
  admin_username      = "azureuser"
  health_probe_id     = azurerm_lb_probe.example.id
  automatic_instance_repair {
    enabled      = true
    grace_period = "PT10M"
  }
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
`az vmss show -g <rg> -n <name> --query 'automaticRepairsPolicy.enabled'`
must return `true`.
```

## References

**MITRE ATT&CK**
  - [`T1485`](https://attack.mitre.org/techniques/T1485/)

**NIST CSF 2.0**
  - [`PR.IP-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`CP-10`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=cp-10)

**Source**
  - [`catalog/ROB-AZURE-VMSS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-AZURE-VMSS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-AZURE-VMSS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-AZURE-VMSS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-AZURE-VMSS-001
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
