---
title: "SEC-AZURE-BASTION-001 — Azure Bastion host using Basic SKU (no shareable links, no RBAC)"
description: "tf-analyze rule SEC-AZURE-BASTION-001 (LOW · security): Azure Bastion host using Basic SKU (no shareable links, no RBAC)"
keywords: "security, low, terraform, iac, azure, mitre-T1133, cwe-272, nist-csf-pr.ac-3, nist-800-53-ac-17"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-BASTION-001 \u2014 Azure Bastion host using Basic SKU (no shareable links, no RBAC)",
  "description": "Upgrade to Standard SKU and enable scale units + the relevant\nStandard-tier features:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-BASTION-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-BASTION-001/"
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
  "keywords": "security, low, terraform, MITRE T1133, CWE-272",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ℹ️ SEC-AZURE-BASTION-001 — Azure Bastion host using Basic SKU (no shareable links, no RBAC)

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-BASTION-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-BASTION-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-BASTION-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure Bastion host using Basic SKU (no shareable links, no RBAC).** This rule has `default_urgency: LOW` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `azurerm_bastion_host` (`sku`) matching `/^Basic$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `azurerm_bastion_host.sku = "Basic"` lacks Standard-tier features:
shareable links, native client tunneling, custom port, host scaling,
and Microsoft-Entra-ID-based access controls (Standard only).

## Why it likely fired

`azurerm_bastion_host.sku = "Basic"` lacks Standard-tier features:
shareable links, native client tunneling, custom port, host scaling,
and Microsoft-Entra-ID-based access controls (Standard only).

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-BASTION-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Upgrade to Standard SKU and enable scale units + the relevant
Standard-tier features:

    resource "azurerm_bastion_host" "main" {
      # ...
      sku                = "Standard"
      scale_units        = 2
      tunneling_enabled  = true
      ip_connect_enabled = true
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "azurerm_bastion_host" "example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Standard"
  scale_units         = 2
  ip_configuration {
    name                 = "config"
    subnet_id            = azurerm_subnet.bastion.id
    public_ip_address_id = azurerm_public_ip.bastion.id
  }
}
```

## Verification

```sh
`az network bastion show -g <rg> -n <name> --query 'sku.name'` must
return `Standard`.
```

## References

**SOC 2 Trust Services Criteria**
  - `CC6.3`

**MITRE ATT&CK**
  - [`T1133`](https://attack.mitre.org/techniques/T1133/)

**CWE**
  - [`CWE-272`](https://cwe.mitre.org/data/definitions/272.html)

**NIST CSF 2.0**
  - [`PR.AC-3`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AC-17`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-17)

**Source**
  - [`catalog/SEC-AZURE-BASTION-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-BASTION-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-BASTION-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-BASTION-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-BASTION-001
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
