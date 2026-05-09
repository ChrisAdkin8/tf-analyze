# 💡 ROB-AZURE-STORAGE-001 — Azure storage account missing blob soft delete

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Azure storage account missing blob soft delete.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_storage_account` (`blob_properties`) — _the resource is missing a required attribute (or nested attribute path)._
2. **`resource_arg`** on `azurerm_storage_account` (`blob_properties.delete_retention_policy.days`) matching `/^[0-6]$/` — _the resource declares the named attribute, but its value matches the rule's pattern._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-AZURE-STORAGE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add `blob_properties` with `delete_retention_policy` and
`container_delete_retention_policy`. Soft delete gives a recovery window
for accidental deletions or ransomware.

    resource "azurerm_storage_account" "example" {
      # ...
      blob_properties {
        delete_retention_policy {
          days = 30
        }
        container_delete_retention_policy {
          days = 30
        }
      }
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_storage_account" "example" {
  name                     = "example"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  blob_properties {
    delete_retention_policy {
      days = 30
    }
    container_delete_retention_policy {
      days = 30
    }
  }
}
```

## Verification

After applying, confirm with:

    az storage account blob-service-properties show \
      --account-name <name> --query deleteRetentionPolicy

The `enabled` field should be `true` and `days` should be >= 7.

## References

**CIS Benchmark**
  - `CIS 3.6`

**Source**
  - [`catalog/ROB-AZURE-STORAGE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-AZURE-STORAGE-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-AZURE-STORAGE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-AZURE-STORAGE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-AZURE-STORAGE-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
