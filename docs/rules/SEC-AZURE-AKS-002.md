# ⚠️ SEC-AZURE-AKS-002 — AKS cluster missing network policy

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

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

**Source**
  - [`catalog/SEC-AZURE-AKS-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-AKS-002.yaml) — canonical YAML

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

[← Index of all rules](./)
