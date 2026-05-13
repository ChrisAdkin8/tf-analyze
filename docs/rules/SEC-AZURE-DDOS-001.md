---
title: "SEC-AZURE-DDOS-001 — Azure Virtual Network missing DDoS protection plan"
description: "tf-analyze rule SEC-AZURE-DDOS-001 (MEDIUM · security): Azure Virtual Network missing DDoS protection plan"
keywords: "security, medium, terraform, iac, azure, cis-6.5, mitre-T1498, cwe-770, d3-nta, nist-csf-pr.pt-4, nist-800-53-sc-5"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-DDOS-001 \u2014 Azure Virtual Network missing DDoS protection plan",
  "description": "Provision a DDoS plan and attach the VNet (note: a single plan can\nbe shared across many VNets to amortize cost):",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-DDOS-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-DDOS-001/"
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
  "keywords": "security, medium, terraform, CIS 6.5, MITRE T1498, CWE-770, D3-NTA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-AZURE-DDOS-001 — Azure Virtual Network missing DDoS protection plan

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-DDOS-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-DDOS-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-DDOS-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure Virtual Network missing DDoS protection plan.** This rule has `default_urgency: MEDIUM` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_virtual_network` (`ddos_protection_plan`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_virtual_network` has no `ddos_protection_plan` block.
Public IPs in this VNet are protected only by Azure's basic DDoS
coverage (volumetric only). Standard tier adds adaptive tuning,
attack analytics, and cost protection.

## Why it likely fired

`azurerm_virtual_network` has no `ddos_protection_plan` block.
Public IPs in this VNet are protected only by Azure's basic DDoS
coverage (volumetric only). Standard tier adds adaptive tuning,
attack analytics, and cost protection.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-DDOS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Provision a DDoS plan and attach the VNet (note: a single plan can
be shared across many VNets to amortize cost):

    resource "azurerm_network_ddos_protection_plan" "main" {
      name                = "ddos-plan"
      location            = azurerm_resource_group.main.location
      resource_group_name = azurerm_resource_group.main.name
    }

    resource "azurerm_virtual_network" "main" {
      # ...
      ddos_protection_plan {
        id     = azurerm_network_ddos_protection_plan.main.id
        enable = true
      }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_virtual_network" "example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  address_space       = ["10.0.0.0/16"]
  ddos_protection_plan {
    id     = azurerm_network_ddos_protection_plan.example.id
    enable = true
  }
}
```

## Verification

```sh
`az network vnet show -g <rg> -n <name> --query 'enableDdosProtection'`
must return `true`.
```

## References

**CIS Benchmark**
  - `CIS 6.5`

**PCI-DSS**
  - `Req-1.3`

**MITRE ATT&CK**
  - [`T1498`](https://attack.mitre.org/techniques/T1498/)

**CWE**
  - [`CWE-770`](https://cwe.mitre.org/data/definitions/770.html)

**MITRE D3FEND**
  - [`D3-NTA`](https://d3fend.mitre.org/technique/D3-NTA/)

**NIST CSF 2.0**
  - [`PR.PT-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-5`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-5)

**Source**
  - [`catalog/SEC-AZURE-DDOS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-DDOS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-DDOS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-DDOS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-DDOS-001
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
