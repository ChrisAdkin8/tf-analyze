# ⚠️ STK-AZURE-AKS-004 — AKS cluster API server is publicly accessible

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

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

[← Index of all rules](./)
