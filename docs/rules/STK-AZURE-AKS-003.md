# ⚠️ STK-AZURE-AKS-003 — AKS cluster workload identity not enabled

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **AKS cluster workload identity not enabled.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_kubernetes_cluster` (`workload_identity_enabled`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_kubernetes_cluster` without `workload_identity_enabled = true`.
Without Workload Identity, pods that need Azure API access must use
a service principal stored in a Secret, or inherit the node pool's
managed identity. Workload Identity issues short-lived tokens per pod
via Azure AD federation — equivalent to GKE Workload Identity or
AWS IRSA.
2. **`hcl_attr`** on `azurerm_kubernetes_cluster` (`workload_identity_enabled`) not equal to `True` — _an attribute value differs from the expected literal._

## Why it likely fired

`azurerm_kubernetes_cluster` without `workload_identity_enabled = true`.
Without Workload Identity, pods that need Azure API access must use
a service principal stored in a Secret, or inherit the node pool's
managed identity. Workload Identity issues short-lived tokens per pod
via Azure AD federation — equivalent to GKE Workload Identity or
AWS IRSA.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-AKS-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable Workload Identity and the OIDC issuer on the cluster:

    resource "azurerm_kubernetes_cluster" "app" {
      oidc_issuer_enabled       = true
      workload_identity_enabled = true
    }

Then bind a User-Assigned Managed Identity to a Kubernetes ServiceAccount
via a `azurerm_federated_identity_credential` resource. Pods annotated
with `azure.workload.identity/client-id` receive short-lived Azure AD
tokens scoped to that identity's role assignments.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  dns_prefix          = "example"
  oidc_issuer_enabled       = true
  workload_identity_enabled = true
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
  --query 'oidcIssuerProfile.enabled'`
and
`az aks show ... --query 'securityProfile.workloadIdentity.enabled'`
both must return `true`.
```

## References

**Source**
  - [`catalog/STK-AZURE-AKS-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-AKS-003.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-AKS-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-AKS-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-AKS-003
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
