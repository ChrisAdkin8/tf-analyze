---
title: "STK-AZURE-EVENT-GRID-001 — Azure Event Grid topic missing managed identity and CMK"
description: "tf-analyze rule STK-AZURE-EVENT-GRID-001 (MEDIUM · stack): Azure Event Grid topic missing managed identity and CMK"
keywords: "stack, medium, terraform, iac, azure, mitre-T1530, cwe-311, d3-ear, nist-csf-pr.ds-1, nist-800-53-sc-13, csa-ccm-cek-03"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AZURE-EVENT-GRID-001 \u2014 Azure Event Grid topic missing managed identity and CMK",
  "description": "Bind a system-assigned identity and use it to grant the topic Key\nVault Crypto Service Encryption User on the CMK:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-EVENT-GRID-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-EVENT-GRID-001/"
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
  "keywords": "stack, medium, terraform, MITRE T1530, CWE-311, D3-EAR",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# 💡 STK-AZURE-EVENT-GRID-001 — Azure Event Grid topic missing managed identity and CMK

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AZURE-EVENT-GRID-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-AZURE-EVENT-GRID-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-AZURE-EVENT-GRID-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure Event Grid topic missing managed identity and CMK.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_eventgrid_topic` (`identity`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_eventgrid_topic` has no `identity` block, so it cannot
bind a customer-managed key for encryption-at-rest. Event payloads
are encrypted only with Microsoft-managed keys.
2. **`resource_missing_arg`** on `azurerm_eventgrid_domain` (`identity`) — _the resource is missing a required attribute (or nested attribute path)._
  Event Grid domain missing managed identity (no CMK possible)

## Why it likely fired

`azurerm_eventgrid_topic` has no `identity` block, so it cannot
bind a customer-managed key for encryption-at-rest. Event payloads
are encrypted only with Microsoft-managed keys.

Event Grid domain missing managed identity (no CMK possible)

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-EVENT-GRID-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Bind a system-assigned identity and use it to grant the topic Key
Vault Crypto Service Encryption User on the CMK:

    resource "azurerm_eventgrid_topic" "main" {
      # ...
      identity { type = "SystemAssigned" }
      inbound_ip_rule { ip_mask = "10.0.0.0/8" action = "Allow" }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_eventgrid_topic" "example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  identity { type = "SystemAssigned" }
}
```

## Verification

```sh
`az eventgrid topic show -g <rg> -n <name> --query 'identity.type'`
must return `SystemAssigned` or `UserAssigned`.
```

## References

**PCI-DSS**
  - `Req-3.4`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**MITRE ATT&CK**
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)

**CWE**
  - [`CWE-311`](https://cwe.mitre.org/data/definitions/311.html)

**MITRE D3FEND**
  - [`D3-EAR`](https://d3fend.mitre.org/technique/D3-EAR/)

**NIST CSF 2.0**
  - [`PR.DS-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-13`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-13)

**CSA CCM v4**
  - [`CEK-03`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/STK-AZURE-EVENT-GRID-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-EVENT-GRID-001.yaml) — canonical YAML

## Family

See also rules in the `STK-AZURE-EVENT-GRID-*` family:

- [`STK-AZURE-EVENT-GRID-002`](./STK-AZURE-EVENT-GRID-002.md) — Azure Event Grid event subscription missing dead-letter destination

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-EVENT-GRID-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-EVENT-GRID-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-EVENT-GRID-001
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
