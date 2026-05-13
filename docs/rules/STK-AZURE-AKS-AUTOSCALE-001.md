---
title: "STK-AZURE-AKS-AUTOSCALE-001 — Azure AKS default node pool missing auto-scaling"
description: "tf-analyze rule STK-AZURE-AKS-AUTOSCALE-001 (LOW · stack): Azure AKS default node pool missing auto-scaling"
keywords: "stack, low, terraform, iac, azure, mitre-T1496, nist-csf-pr.pt-1"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AZURE-AKS-AUTOSCALE-001 \u2014 Azure AKS default node pool missing auto-scaling",
  "description": "Enable cluster autoscaler on the default node pool:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-AKS-AUTOSCALE-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-AKS-AUTOSCALE-001/"
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
  "keywords": "stack, low, terraform, MITRE T1496",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ℹ️ STK-AZURE-AKS-AUTOSCALE-001 — Azure AKS default node pool missing auto-scaling

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AZURE-AKS-AUTOSCALE-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-AZURE-AKS-AUTOSCALE-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-AZURE-AKS-AUTOSCALE-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure AKS default node pool missing auto-scaling.** This rule has `default_urgency: LOW` and operates on a module blast radius. 

## What this checks

1. **`resource_body_contains`** on `azurerm_kubernetes_cluster` matching `/enable_auto_scaling\s*=\s*false/` — _the resource body matches a regex inside the block._
  `azurerm_kubernetes_cluster.default_node_pool.enable_auto_scaling = false`
explicitly disables the cluster autoscaler. Fixed node count
wastes capacity at low load and hits ceiling at high load.
2. **`resource_body_contains`** on `azurerm_kubernetes_cluster_node_pool` matching `/enable_auto_scaling\s*=\s*false/` — _the resource body matches a regex inside the block._
  Standalone AKS node pool with auto-scaling disabled

## Why it likely fired

`azurerm_kubernetes_cluster.default_node_pool.enable_auto_scaling = false`
explicitly disables the cluster autoscaler. Fixed node count
wastes capacity at low load and hits ceiling at high load.

Standalone AKS node pool with auto-scaling disabled

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-AKS-AUTOSCALE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable cluster autoscaler on the default node pool:

    resource "azurerm_kubernetes_cluster" "main" {
      default_node_pool {
        name                = "default"
        enable_auto_scaling = true
        min_count           = 1
        max_count           = 10
        vm_size             = "Standard_D2s_v3"
      }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "example"
  default_node_pool {
    name                = "default"
    enable_auto_scaling = true
    min_count           = 1
    max_count           = 10
    vm_size             = "Standard_D2s_v3"
  }
  identity { type = "SystemAssigned" }
}
```

## Verification

```sh
`az aks show -g <rg> -n <name> --query 'agentPoolProfiles[0].enableAutoScaling'`
must return `true`.
```

## References

**MITRE ATT&CK**
  - [`T1496`](https://attack.mitre.org/techniques/T1496/)

**NIST CSF 2.0**
  - [`PR.PT-1`](https://www.nist.gov/cyberframework)

**Source**
  - [`catalog/STK-AZURE-AKS-AUTOSCALE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-AKS-AUTOSCALE-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-AKS-AUTOSCALE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-AKS-AUTOSCALE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-AKS-AUTOSCALE-001
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
