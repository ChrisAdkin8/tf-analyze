# ⚠️ SEC-AZURE-ACR-001 — Azure Container Registry admin account enabled

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Azure Container Registry admin account enabled.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`hcl_attr`** on `azurerm_container_registry` (`admin_enabled`) not equal to `False` — _an attribute value differs from the expected literal._
  `azurerm_container_registry` with `admin_enabled = true`. The admin
account uses a shared username and password with full read/write
access to all repositories in the registry. It cannot be scoped,
audited per-user, or rotated without re-pushing credentials to all
consumers. Equivalent to keeping the root account active in an IAM
system. Use Entra ID service principals or managed identities with
AcrPull / AcrPush role assignments instead.

## Why it likely fired

`azurerm_container_registry` with `admin_enabled = true`. The admin
account uses a shared username and password with full read/write
access to all repositories in the registry. It cannot be scoped,
audited per-user, or rotated without re-pushing credentials to all
consumers. Equivalent to keeping the root account active in an IAM
system. Use Entra ID service principals or managed identities with
AcrPull / AcrPush role assignments instead.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-ACR-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Disable the admin account and use Entra ID authentication:

    resource "azurerm_container_registry" "app" {
      name                = "acrapp"
      resource_group_name = azurerm_resource_group.app.name
      location            = azurerm_resource_group.app.location
      sku                 = "Standard"
      admin_enabled       = false
    }

    resource "azurerm_role_assignment" "aks_pull" {
      scope                = azurerm_container_registry.app.id
      role_definition_name = "AcrPull"
      principal_id         = azurerm_kubernetes_cluster.app.kubelet_identity[0].object_id
    }

ACR supports task identities, managed identities for Azure services,
and service principal tokens — none of which need the admin account.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_container_registry" "example" {
  name                = "exampleacr"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Standard"
  admin_enabled       = false
}
```

## Verification

```sh
`az acr show --name <registry> --resource-group <rg> \
  --query 'adminUserEnabled'`
must return `false`.
```

## References

**Source**
  - [`catalog/SEC-AZURE-ACR-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-ACR-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-ACR-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-ACR-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-ACR-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
