---
title: "SEC-AZURE-EXPRESSROUTE-001 — Azure ExpressRoute port missing MACsec encryption"
description: "tf-analyze rule SEC-AZURE-EXPRESSROUTE-001 (MEDIUM · security): Azure ExpressRoute port missing MACsec encryption"
keywords: "security, medium, terraform, iac, azure, mitre-T1040, cwe-311, d3-et, nist-csf-pr.ds-2, nist-800-53-sc-8"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-EXPRESSROUTE-001 \u2014 Azure ExpressRoute port missing MACsec encryption",
  "description": "Configure MACsec on ExpressRoute Direct ports for compliance-driven\nworkloads (PCI-DSS, FedRAMP-High):",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-EXPRESSROUTE-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-EXPRESSROUTE-001/"
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
  "keywords": "security, medium, terraform, MITRE T1040, CWE-311, D3-ET",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-AZURE-EXPRESSROUTE-001 — Azure ExpressRoute port missing MACsec encryption

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-EXPRESSROUTE-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-EXPRESSROUTE-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-EXPRESSROUTE-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure ExpressRoute port missing MACsec encryption.** This rule has `default_urgency: MEDIUM` and operates on a module blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_express_route_port` (`macsec_cipher`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_express_route_port` has no `macsec_cipher` (and the
paired key references). MACsec is a layer-2 encryption protocol
for ExpressRoute Direct ports — without it, traffic between the
Microsoft Enterprise Edge and customer router is unencrypted.

## Why it likely fired

`azurerm_express_route_port` has no `macsec_cipher` (and the
paired key references). MACsec is a layer-2 encryption protocol
for ExpressRoute Direct ports — without it, traffic between the
Microsoft Enterprise Edge and customer router is unencrypted.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-EXPRESSROUTE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Configure MACsec on ExpressRoute Direct ports for compliance-driven
workloads (PCI-DSS, FedRAMP-High):

    resource "azurerm_express_route_port" "main" {
      # ...
      macsec_cipher                 = "GcmAes128"
      macsec_ckn_keyvault_secret_id = azurerm_key_vault_secret.ckn.id
      macsec_cak_keyvault_secret_id = azurerm_key_vault_secret.cak.id
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_express_route_port" "example" {
  name                = "er-port"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  peering_location    = "Equinix-Washington-DC-DC2"
  bandwidth_in_gbps   = 10
  encapsulation       = "Dot1Q"
  macsec_cipher       = "GcmAes128"
}
```

## Verification

```sh
`az network express-route port show -g <rg> -n <name> --query 'links[0].macSecConfig'`
must return a non-null config.
```

## References

**PCI-DSS**
  - `Req-4.1`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**MITRE ATT&CK**
  - [`T1040`](https://attack.mitre.org/techniques/T1040/)

**CWE**
  - [`CWE-311`](https://cwe.mitre.org/data/definitions/311.html)

**MITRE D3FEND**
  - [`D3-ET`](https://d3fend.mitre.org/technique/D3-ET/)

**NIST CSF 2.0**
  - [`PR.DS-2`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-8`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-8)

**Source**
  - [`catalog/SEC-AZURE-EXPRESSROUTE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-EXPRESSROUTE-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-EXPRESSROUTE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-EXPRESSROUTE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-EXPRESSROUTE-001
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
