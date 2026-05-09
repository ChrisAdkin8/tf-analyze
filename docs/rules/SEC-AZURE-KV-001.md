# ⚠️ SEC-AZURE-KV-001 — Azure Key Vault missing purge protection or soft delete

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Azure Key Vault missing purge protection or soft delete.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`resource_arg`** on `azurerm_key_vault` (`purge_protection_enabled`) matching `/^false$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
2. **`resource_missing_arg`** on `azurerm_key_vault` (`purge_protection_enabled`) — _the resource is missing a required attribute (or nested attribute path)._
3. **`resource_arg`** on `azurerm_key_vault` (`soft_delete_retention_days`) matching `/^[0-6]$/` — _the resource declares the named attribute, but its value matches the rule's pattern._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-KV-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `purge_protection_enabled = true` and `soft_delete_retention_days = 90`.
Without purge protection, an attacker (or accident) that deletes the Key Vault
bypasses the soft-delete window by purging — secrets, keys, and certificates
are gone permanently.

    resource "azurerm_key_vault" "example" {
      # ...
      purge_protection_enabled    = true
      soft_delete_retention_days  = 90
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_key_vault" "example" {
  # ... other arguments ...
  purge_protection_enabled    = true
  soft_delete_retention_days  = 90
}
```

## Verification

After applying, confirm with:

    az keyvault show --name <name> \
      --query '{purgeProtection:properties.enablePurgeProtection,softDelete:properties.enableSoftDelete}'

Both values should return `true`.

## References

**CIS Benchmark**
  - `CIS 8.4`

**MITRE ATT&CK**
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)

**Source**
  - [`catalog/SEC-AZURE-KV-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-KV-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-KV-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-KV-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-KV-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
