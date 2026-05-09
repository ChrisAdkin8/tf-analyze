---
title: "STK-AZURE-AKS-004 — AKS cluster API server is publicly accessible"
description: "tf-analyze rule STK-AZURE-AKS-004 (HIGH · stack): AKS cluster API server is publicly accessible"
keywords: "stack, high, terraform, iac, azure"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AZURE-AKS-004 \u2014 AKS cluster API server is publicly accessible",
  "description": "Enable the private cluster feature so the API server is only reachable\nfrom within the VNet:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-AKS-004/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-AKS-004/"
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
  "keywords": "stack, high, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-AZURE-AKS-004 — AKS cluster API server is publicly accessible

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AZURE-AKS-004" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-AZURE-AKS-004" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-AZURE-AKS-004 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **AKS cluster API server is publicly accessible.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_kubernetes_cluster` (`private_cluster_enabled`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_kubernetes_cluster` without `private_cluster_enabled = true`.
The Kubernetes API server is reachable over the internet. Any credential
(service account token, kubeconfig) leaked from CI or developer machines
can be used to reach the API from anywhere.
2. **`hcl_attr`** on `azurerm_kubernetes_cluster` (`private_cluster_enabled`) not equal to `True` — _an attribute value differs from the expected literal._

## Why it likely fired

`azurerm_kubernetes_cluster` without `private_cluster_enabled = true`.
The Kubernetes API server is reachable over the internet. Any credential
(service account token, kubeconfig) leaked from CI or developer machines
can be used to reach the API from anywhere.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-AKS-004` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable the private cluster feature so the API server is only reachable
from within the VNet:

    resource "azurerm_kubernetes_cluster" "app" {
      private_cluster_enabled             = true
      private_cluster_public_fqdn_enabled = false
    }

When the cluster is private, `kubectl` must run from a jumpbox or VPN
host inside (or peered with) the cluster VNet. Integrate with Azure
Private DNS for internal FQDN resolution. Equivalent to GKE
`private_cluster_config.enable_private_endpoint = true`.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  dns_prefix          = "example"
  private_cluster_enabled = true
  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }
  identity { type = "SystemAssigned" }
}
```

## Verification

```sh
`az aks show --name <cluster> --resource-group <rg> \
  --query 'enablePrivateCluster'`
must return `true`.
```

## References

**Source**
  - [`catalog/STK-AZURE-AKS-004.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-AKS-004.yaml) — canonical YAML

## Family

See also rules in the `STK-AZURE-AKS-*` family:

- [`STK-AZURE-AKS-003`](./STK-AZURE-AKS-003.md) — AKS cluster workload identity not enabled
- [`STK-AZURE-AKS-005`](./STK-AZURE-AKS-005.md) — AKS cluster API server missing authorized IP ranges

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-AKS-004    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-AKS-004` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-AKS-004
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
