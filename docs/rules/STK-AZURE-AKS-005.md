# 💡 STK-AZURE-AKS-005 — AKS cluster API server missing authorized IP ranges

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **AKS cluster API server missing authorized IP ranges.** This rule has `default_urgency: MEDIUM` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_kubernetes_cluster` (`api_server_access_profile.authorized_ip_ranges`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_kubernetes_cluster` without
`api_server_access_profile { authorized_ip_ranges }`. The public
Kubernetes API endpoint accepts connections from any IP address.
Even with valid credentials required, brute-force and credential-
stuffing attacks can target the API from anywhere on the internet.

## Why it likely fired

`azurerm_kubernetes_cluster` without
`api_server_access_profile { authorized_ip_ranges }`. The public
Kubernetes API endpoint accepts connections from any IP address.
Even with valid credentials required, brute-force and credential-
stuffing attacks can target the API from anywhere on the internet.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-AKS-005` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Restrict API server access to known CIDRs (CI runners, operator VPN
egress IPs, bastion host subnets):

    resource "azurerm_kubernetes_cluster" "app" {
      api_server_access_profile {
        authorized_ip_ranges = [
          "203.0.113.0/24",  # CI runner egress
          "10.0.0.0/8",      # internal VNet
        ]
      }
    }

The recommended target is `private_cluster_enabled = true`
(STK-AZURE-AKS-004). Authorized IP ranges are a defence-in-depth
layer for clusters that must retain a public endpoint.
Equivalent to GKE `master_authorized_networks_config`.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  dns_prefix          = "example"
  api_server_access_profile {
    authorized_ip_ranges = ["203.0.113.0/24"]
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
  --query 'apiServerAccessProfile.authorizedIpRanges'`
must return a non-empty list.
```

## References

**Source**
  - [`catalog/STK-AZURE-AKS-005.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-AKS-005.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-AKS-005    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-AKS-005` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-AKS-005
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
