# 💡 SEC-AZURE-EVENTHUB-001 — Event Hub namespace does not use CMK encryption

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Event Hub namespace does not use CMK encryption.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_eventhub_namespace` (`customer_managed_key`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_eventhub_namespace` has no `customer_managed_key` block.
Without a CMK, Event Hub data is encrypted with a Microsoft-managed key
that cannot be revoked, audited independently, or rotated on a custom
schedule. CMK encryption is required for PCI-DSS and many enterprise
compliance frameworks.

## Why it likely fired

`azurerm_eventhub_namespace` has no `customer_managed_key` block.
Without a CMK, Event Hub data is encrypted with a Microsoft-managed key
that cannot be revoked, audited independently, or rotated on a custom
schedule. CMK encryption is required for PCI-DSS and many enterprise
compliance frameworks.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-EVENTHUB-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable CMK encryption on the Event Hub namespace:

    resource "azurerm_eventhub_namespace" "main" {
      # ...
      identity {
        type = "SystemAssigned"
      }

      customer_managed_key {
        key_vault_key_id       = azurerm_key_vault_key.evhub.id
        infrastructure_encryption_enabled = true
      }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_eventhub_namespace" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Premium"
  identity {
    type = "SystemAssigned"
  }
  customer_managed_key {
    key_vault_key_id = azurerm_key_vault_key.example.id
    infrastructure_encryption_enabled = true
  }
}
```

## Verification

```sh
`az eventhubs namespace show --name <name> --resource-group <rg> \
  --query 'encryption.keySource'`
must return `"Microsoft.KeyVault"`.
```

## References

**PCI-DSS**
  - `Req-3.4`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**Source**
  - [`catalog/SEC-AZURE-EVENTHUB-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-EVENTHUB-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-EVENTHUB-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-EVENTHUB-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-EVENTHUB-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
