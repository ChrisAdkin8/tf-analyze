# 💡 SEC-AZURE-KV-003 — Azure Key Vault key missing rotation policy

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Azure Key Vault key missing rotation policy.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_key_vault_key` (`rotation_policy.automatic.time_before_expiry`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_key_vault_key` without a `rotation_policy { automatic {} }`
block. The key material never rotates — a compromised key can decrypt
all data encrypted with it, past and future, until the key is
manually rotated. Equivalent to GCP `STK-GCP-KMS-001` (KMS rotation
period missing) and AWS `SEC-AWS-KMS-001` (enable_key_rotation).

## Why it likely fired

`azurerm_key_vault_key` without a `rotation_policy { automatic {} }`
block. The key material never rotates — a compromised key can decrypt
all data encrypted with it, past and future, until the key is
manually rotated. Equivalent to GCP `STK-GCP-KMS-001` (KMS rotation
period missing) and AWS `SEC-AWS-KMS-001` (enable_key_rotation).

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-KV-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a rotation policy to every Key Vault key:

    resource "azurerm_key_vault_key" "app" {
      name         = "app-key"
      key_vault_id = azurerm_key_vault.app.id
      key_type     = "RSA"
      key_size     = 2048
      key_opts     = ["decrypt", "encrypt", "sign", "verify"]

      rotation_policy {
        automatic {
          time_before_expiry = "P30D"  # rotate 30 days before expiry
        }
        expire_after         = "P90D"  # 90-day key lifetime
        notify_before_expiry = "P29D"
      }
    }

`time_before_expiry` uses ISO 8601 duration format (P30D = 30 days).
Set the key lifetime (`expire_after`) to ≤ 90 days for CIS compliance.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_key_vault_key" "example" {
  name         = "example"
  key_vault_id = azurerm_key_vault.example.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "sign", "verify"]
  rotation_policy {
    automatic {
      time_before_expiry = "P30D"
    }
    expire_after         = "P90D"
    notify_before_expiry = "P29D"
  }
}
```

## Verification

```sh
`az keyvault key show --vault-name <vault> --name <key> \
  --query 'attributes.{Expires:expires,Created:created}'`
Confirm a rotation policy exists in the Azure Portal:
Key Vault → Keys → <key> → Rotation policy.
```

## References

**CIS Benchmark**
  - `CIS 8.6`

**Source**
  - [`catalog/SEC-AZURE-KV-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-KV-003.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-KV-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-KV-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-KV-003
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
