---
title: "STK-AZURE-NSG-001 — Azure NSG rule open to the internet on sensitive ports"
description: "tf-analyze rule STK-AZURE-NSG-001 (HIGH · stack): Azure NSG rule open to the internet on sensitive ports"
keywords: "stack, high, terraform, iac, azure, cis-6.1, cis-6.2, cwe-284, d3-iaa"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AZURE-NSG-001 \u2014 Azure NSG rule open to the internet on sensitive ports",
  "description": "Replace `source_address_prefix = \"*\"` with a specific CIDR or Azure service\ntag. For SSH/RDP, use Azure Bastion instead of opening ports to the internet.\nFor internal services, use VNet service tags (`VirtualNetwork`) rather than `*`.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-NSG-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-NSG-001/"
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
  "keywords": "stack, high, terraform, CIS 6.1, CIS 6.2, CWE-284, D3-IAA",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-AZURE-NSG-001 — Azure NSG rule open to the internet on sensitive ports

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AZURE-NSG-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-AZURE-NSG-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-AZURE-NSG-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure NSG rule open to the internet on sensitive ports.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`grep`** matching `/source_address_prefix\s*=\s*"\*"/` — _a textual regex matched somewhere in the file._
2. **`grep`** matching `/source_address_prefix\s*=\s*"Internet"/` — _a textual regex matched somewhere in the file._
3. **`grep`** matching `/source_address_prefix\s*=\s*"0\.0\.0\.0/0"/` — _a textual regex matched somewhere in the file._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-NSG-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace `source_address_prefix = "*"` with a specific CIDR or Azure service
tag. For SSH/RDP, use Azure Bastion instead of opening ports to the internet.
For internal services, use VNet service tags (`VirtualNetwork`) rather than `*`.

    # Bad — any IP on the internet can reach this port
    source_address_prefix = "*"

    # Better — restrict to a known CIDR
    source_address_prefix = "10.0.0.0/8"

    # Best for management ports — use Azure Bastion and remove the rule
If port 22 or 3389 is involved, treat this as CRITICAL and remediate
immediately.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_network_security_rule" "example" {
  name                        = "allow-https"
  resource_group_name         = azurerm_resource_group.example.name
  network_security_group_name = azurerm_network_security_group.example.name
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "203.0.113.0/24"
  destination_address_prefix  = "*"
}
```

## Verification

After applying, confirm with:

    az network nsg rule list --nsg-name <nsg> --resource-group <rg> \
      --output table

No rules should have `*` or `Internet` as source with port 22 or 3389 as
destination.

## References

**CIS Benchmark**
  - `CIS 6.1`
  - `CIS 6.2`

**CWE**
  - [`CWE-284`](https://cwe.mitre.org/data/definitions/284.html)

**MITRE D3FEND**
  - [`D3-IAA`](https://d3fend.mitre.org/technique/D3-IAA/)

**Source**
  - [`catalog/STK-AZURE-NSG-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-NSG-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-NSG-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-NSG-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-NSG-001
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
