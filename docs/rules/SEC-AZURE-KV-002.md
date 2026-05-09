# ⚠️ SEC-AZURE-KV-002 — Key Vault missing network ACL deny-by-default

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Key Vault missing network ACL deny-by-default.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_key_vault` (`network_acls.default_action`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_key_vault` with no `network_acls` block. The default
network access is `"Allow"` — the vault endpoint accepts requests
from any IP. Any credential that can reach the vault over the public
internet can enumerate and read secrets.
2. **`hcl_attr`** on `azurerm_key_vault` (`network_acls.default_action`) not equal to `"Deny"` — _an attribute value differs from the expected literal._
  `network_acls.default_action` is set to `"Allow"`. All traffic is
permitted unless an explicit deny IP rule matches first.

## Why it likely fired

`azurerm_key_vault` with no `network_acls` block. The default
network access is `"Allow"` — the vault endpoint accepts requests
from any IP. Any credential that can reach the vault over the public
internet can enumerate and read secrets.

`network_acls.default_action` is set to `"Allow"`. All traffic is
permitted unless an explicit deny IP rule matches first.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-KV-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set the default action to `"Deny"` and enumerate the allowed CIDRs /
VNet subnets explicitly:

    resource "azurerm_key_vault" "app" {
      name = "kv-app"
      # ...

      network_acls {
        default_action             = "Deny"
        bypass                     = "AzureServices"
        ip_rules                   = ["203.0.113.0/24"]
        virtual_network_subnet_ids = [azurerm_subnet.app.id]
      }
    }

`bypass = "AzureServices"` allows diagnostic and monitoring services
that run in the Azure backbone to reach the vault — omitting it breaks
Key Vault audit logging.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_key_vault" "example" {
  # ... other arguments ...
  network_acls {
    default_action = "Deny"
    bypass         = ["AzureServices"]
    ip_rules       = []
  }
}
```

## Verification

```sh
`az keyvault show --name <name> --resource-group <rg> \
  --query 'properties.networkAcls.defaultAction'`
must return `"Deny"`.
```

## References

**CIS Benchmark**
  - `CIS 8.5`

**MITRE ATT&CK**
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)
  - [`T1133`](https://attack.mitre.org/techniques/T1133/)

**Source**
  - [`catalog/SEC-AZURE-KV-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-KV-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-KV-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-KV-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-KV-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
