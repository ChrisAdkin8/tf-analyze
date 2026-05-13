---
title: "SEC-AZURE-AKS-OMS-001 — Azure AKS cluster missing Container Insights (OMS agent)"
description: "tf-analyze rule SEC-AZURE-AKS-OMS-001 (MEDIUM · security): Azure AKS cluster missing Container Insights (OMS agent)"
keywords: "security, medium, terraform, iac, azure, mitre-T1530, cwe-778, d3-iaa, nist-csf-de.cm-1, nist-800-53-au-2, csa-ccm-log-08"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-AKS-OMS-001 \u2014 Azure AKS cluster missing Container Insights (OMS agent)",
  "description": "Enable Container Insights via the OMS agent:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-AKS-OMS-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-AKS-OMS-001/"
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
  "keywords": "security, medium, terraform, MITRE T1530, CWE-778, D3-IAA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-AZURE-AKS-OMS-001 — Azure AKS cluster missing Container Insights (OMS agent)

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-AKS-OMS-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-AKS-OMS-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-AKS-OMS-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure AKS cluster missing Container Insights (OMS agent).** This rule has `default_urgency: MEDIUM` and operates on a module blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_kubernetes_cluster` (`oms_agent`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_kubernetes_cluster` has no `oms_agent` block. Container
Insights metrics, container logs, and Prometheus scraping are
not exported to Log Analytics — incident response is blind to
pod-level signals.

## Why it likely fired

`azurerm_kubernetes_cluster` has no `oms_agent` block. Container
Insights metrics, container logs, and Prometheus scraping are
not exported to Log Analytics — incident response is blind to
pod-level signals.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-AKS-OMS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable Container Insights via the OMS agent:

    resource "azurerm_kubernetes_cluster" "main" {
      # ...
      oms_agent {
        log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
      }
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "example"
  default_node_pool { name = "default" node_count = 1 vm_size = "Standard_D2s_v3" }
  identity { type = "SystemAssigned" }
  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id
  }
}
```

## Verification

```sh
`az aks show -g <rg> -n <name> --query 'addonProfiles.omsagent.enabled'`
must return `true`.
```

## References

**SOC 2 Trust Services Criteria**
  - `CC7.2`

**MITRE ATT&CK**
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)

**CWE**
  - [`CWE-778`](https://cwe.mitre.org/data/definitions/778.html)

**MITRE D3FEND**
  - [`D3-IAA`](https://d3fend.mitre.org/technique/D3-IAA/)

**NIST CSF 2.0**
  - [`DE.CM-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AU-2`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=au-2)

**CSA CCM v4**
  - [`LOG-08`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AZURE-AKS-OMS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-AKS-OMS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-AKS-OMS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-AKS-OMS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-AKS-OMS-001
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
