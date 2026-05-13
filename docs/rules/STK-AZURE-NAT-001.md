---
title: "STK-AZURE-NAT-001 — Azure NAT Gateway missing diagnostic settings"
description: "tf-analyze rule STK-AZURE-NAT-001 (MEDIUM · stack): Azure NAT Gateway missing diagnostic settings"
keywords: "stack, medium, terraform, iac, azure, mitre-T1562.008, cwe-778, d3-iaa, nist-csf-de.cm-1, nist-800-53-au-2"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AZURE-NAT-001 \u2014 Azure NAT Gateway missing diagnostic settings",
  "description": "Ship NAT Gateway metrics to Log Analytics for SNAT exhaustion\nalerting:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-NAT-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-NAT-001/"
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
  "keywords": "stack, medium, terraform, MITRE T1562.008, CWE-778, D3-IAA",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# 💡 STK-AZURE-NAT-001 — Azure NAT Gateway missing diagnostic settings

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AZURE-NAT-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-AZURE-NAT-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-AZURE-NAT-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure NAT Gateway missing diagnostic settings.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_absent`** on `azurerm_monitor_diagnostic_setting` — _the corpus is missing a resource type we expected to find given other resources present._
  `azurerm_nat_gateway` is declared but no
`azurerm_monitor_diagnostic_setting` is bound. SNAT port usage,
drop rates, and idle-timeout failures are not logged.

## Why it likely fired

`azurerm_nat_gateway` is declared but no
`azurerm_monitor_diagnostic_setting` is bound. SNAT port usage,
drop rates, and idle-timeout failures are not logged.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-NAT-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Ship NAT Gateway metrics to Log Analytics for SNAT exhaustion
alerting:

    resource "azurerm_monitor_diagnostic_setting" "nat" {
      name                       = "nat-diag"
      target_resource_id         = azurerm_nat_gateway.main.id
      log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
      metric { category = "AllMetrics" enabled = true }
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_monitor_diagnostic_setting" "nat" {
  name                       = "nat-diag"
  target_resource_id         = azurerm_nat_gateway.example.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id
  metric {
    category = "AllMetrics"
    enabled  = true
  }
}
```

## Verification

```sh
`az monitor diagnostic-settings list --resource <nat-gw-id>` must
return at least one configuration.
```

## References

**PCI-DSS**
  - `Req-10.2`

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
  - [`catalog/STK-AZURE-NAT-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-NAT-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-NAT-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-NAT-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-NAT-001
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
