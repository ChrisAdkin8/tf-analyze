# ⚠️ SEC-AZURE-AKS-001 — AKS cluster RBAC disabled

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **AKS cluster RBAC disabled.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`resource_arg`** on `azurerm_kubernetes_cluster` (`role_based_access_control_enabled`) matching `/^false$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
2. **`resource_missing_arg`** on `azurerm_kubernetes_cluster` (`azure_active_directory_role_based_access_control`) — _the resource is missing a required attribute (or nested attribute path)._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-AKS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `role_based_access_control_enabled = true` and configure
`azure_active_directory_role_based_access_control`. Without RBAC, any
authenticated user can perform any action in the cluster.

    resource "azurerm_kubernetes_cluster" "example" {
      # ...
      role_based_access_control_enabled = true

      azure_active_directory_role_based_access_control {
        managed                = true
        admin_group_object_ids = [var.aks_admin_group_id]
        azure_rbac_enabled     = true
      }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                              = "example"
  resource_group_name               = azurerm_resource_group.example.name
  location                          = azurerm_resource_group.example.location
  dns_prefix                        = "example"
  role_based_access_control_enabled = true
  azure_active_directory_role_based_access_control {
    managed            = true
    azure_rbac_enabled = true
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

After applying, confirm with:

    az aks show --name <name> --resource-group <rg> --query 'enableRBAC'

The command should return `true`.

## References

**CIS Benchmark**
  - `CIS 5.2`

**Source**
  - [`catalog/SEC-AZURE-AKS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-AKS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-AKS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-AKS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-AKS-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
