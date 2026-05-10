---
title: "SEC-AZURE-AKS-002 — AKS cluster missing network policy"
description: "tf-analyze rule SEC-AZURE-AKS-002 (HIGH · security): AKS cluster missing network policy"
keywords: "security, high, terraform, iac, azure, cis-5.3, mitre-T1133, mitre-T1611"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-AKS-002 \u2014 AKS cluster missing network policy",
  "description": "Set a network policy in the cluster's `network_profile` block:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-AKS-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-AKS-002/"
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
  "keywords": "security, high, terraform, CIS 5.3, MITRE T1133, MITRE T1611",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AZURE-AKS-002 — AKS cluster missing network policy

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-AKS-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-AKS-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-AKS-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **AKS cluster missing network policy.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_kubernetes_cluster` (`network_profile.network_policy`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_kubernetes_cluster` without a `network_profile { network_policy }` setting.
Without a network policy, all pods in the cluster can communicate freely — a
compromised pod can reach every other pod and the Kubernetes API on any port.
With `network_policy = "azure"` (Azure CNI) or `network_policy = "calico"`,
pods are isolated by default and can only reach what a `NetworkPolicy` manifest
explicitly allows.

## Why it likely fired

`azurerm_kubernetes_cluster` without a `network_profile { network_policy }` setting.
Without a network policy, all pods in the cluster can communicate freely — a
compromised pod can reach every other pod and the Kubernetes API on any port.
With `network_policy = "azure"` (Azure CNI) or `network_policy = "calico"`,
pods are isolated by default and can only reach what a `NetworkPolicy` manifest
explicitly allows.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-AKS-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set a network policy in the cluster's `network_profile` block:

    resource "azurerm_kubernetes_cluster" "app" {
      network_profile {
        network_plugin = "azure"
        network_policy = "azure"   # or "calico" / "cilium"
      }
    }

After enabling, deploy Kubernetes `NetworkPolicy` objects to restrict
pod-to-pod and pod-to-API-server traffic to the minimum required.
Without `NetworkPolicy` manifests the CNI allows all traffic even with
the policy engine installed.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  dns_prefix          = "example"
  network_profile {
    network_plugin = "azure"
    network_policy = "azure"
  }
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
  --query 'networkProfile.networkPolicy'`
must return `"azure"`, `"calico"`, or `"cilium"` (not `null` or `"none"`).
```

## References

**CIS Benchmark**
  - `CIS 5.3`

**MITRE ATT&CK**
  - [`T1133`](https://attack.mitre.org/techniques/T1133/)
  - [`T1611`](https://attack.mitre.org/techniques/T1611/)

**Source**
  - [`catalog/SEC-AZURE-AKS-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-AKS-002.yaml) — canonical YAML

## Family

See also rules in the `SEC-AZURE-AKS-*` family:

- [`SEC-AZURE-AKS-001`](./SEC-AZURE-AKS-001.md) — AKS cluster RBAC disabled

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-AKS-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-AKS-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-AKS-002
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
