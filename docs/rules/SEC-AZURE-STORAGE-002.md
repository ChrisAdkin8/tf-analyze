# ⚠️ SEC-AZURE-STORAGE-002 — Azure storage account allows public blob access

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Azure storage account allows public blob access.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `azurerm_storage_account` (`allow_blob_public_access`) matching `/^true$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
2. **`resource_arg`** on `azurerm_storage_account` (`allow_nested_items_to_be_public`) matching `/^true$/` — _the resource declares the named attribute, but its value matches the rule's pattern._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-STORAGE-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `allow_nested_items_to_be_public = false` (provider v3+). Public blob
access allows anonymous reads of any blob in any container with public access
— the most common cause of cloud data breaches.

    resource "azurerm_storage_account" "example" {
      # ...
      allow_nested_items_to_be_public = false
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_storage_account" "example" {
  # ... other arguments ...
  allow_nested_items_to_be_public = false
}
```

## Verification

After applying, confirm with:

    az storage account show --name <name> --query allowBlobPublicAccess

The command should return `false`.

## References

**CIS Benchmark**
  - `CIS 3.7`

**Source**
  - [`catalog/SEC-AZURE-STORAGE-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-STORAGE-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-STORAGE-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-STORAGE-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-STORAGE-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
