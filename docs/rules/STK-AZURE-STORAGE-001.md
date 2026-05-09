# 💡 STK-AZURE-STORAGE-001 — Azure storage account missing blob versioning

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Azure storage account missing blob versioning.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_storage_account` (`blob_properties.versioning_enabled`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_storage_account` without
`blob_properties { versioning_enabled = true }`. Object overwrites and
deletes are permanent. A ransomware playbook or accidental
`az storage blob delete` is unrecoverable without versioning.
2. **`hcl_attr`** on `azurerm_storage_account` (`blob_properties.versioning_enabled`) not equal to `True` — _an attribute value differs from the expected literal._

## Why it likely fired

`azurerm_storage_account` without
`blob_properties { versioning_enabled = true }`. Object overwrites and
deletes are permanent. A ransomware playbook or accidental
`az storage blob delete` is unrecoverable without versioning.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-STORAGE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable versioning in the `blob_properties` block:

    resource "azurerm_storage_account" "app" {
      blob_properties {
        versioning_enabled = true
        delete_retention_policy {
          days = 7
        }
        container_delete_retention_policy {
          days = 7
        }
      }
    }

Pair with a lifecycle management rule to expire non-current versions
after N days to control storage costs. Azure Storage versioning is
equivalent to S3 versioning (ROB-AWS-S3-001) and GCS versioning
(STK-GCP-BUCKET-001).

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
    versioning_enabled = true
  }
}
```

## Verification

```sh
`az storage account blob-service-properties show \
  --account-name <name> --query 'isVersioningEnabled'`
must return `true`.
```

## References

**Source**
  - [`catalog/STK-AZURE-STORAGE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-STORAGE-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-STORAGE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-STORAGE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-STORAGE-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
