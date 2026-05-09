# ⚠️ SEC-AZURE-REDIS-001 — Azure Redis Cache allows non-TLS connections

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Azure Redis Cache allows non-TLS connections.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `azurerm_redis_cache` (`enable_non_ssl_port`) matching `/^true$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `azurerm_redis_cache` has `enable_non_ssl_port = true`. This opens
port 6379 for unencrypted Redis connections. Cache data — which often
includes session tokens, application state, and materialised query
results — is transmitted in cleartext over the network.
2. **`resource_arg`** on `azurerm_redis_cache` (`minimum_tls_version`) — _the resource declares the named attribute, but its value matches the rule's pattern._
  `azurerm_redis_cache` has `minimum_tls_version` below 1.2 or absent.
TLS 1.0 and 1.1 are vulnerable to POODLE, BEAST, and related attacks.
Require TLS 1.2 as the minimum.

## Why it likely fired

`azurerm_redis_cache` has `enable_non_ssl_port = true`. This opens
port 6379 for unencrypted Redis connections. Cache data — which often
includes session tokens, application state, and materialised query
results — is transmitted in cleartext over the network.

`azurerm_redis_cache` has `minimum_tls_version` below 1.2 or absent.
TLS 1.0 and 1.1 are vulnerable to POODLE, BEAST, and related attacks.
Require TLS 1.2 as the minimum.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-REDIS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Disable the non-SSL port and enforce TLS 1.2:

    resource "azurerm_redis_cache" "main" {
      # ...
      enable_non_ssl_port = false
      minimum_tls_version = "1.2"
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_redis_cache" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  capacity            = 1
  family              = "C"
  sku_name            = "Standard"
  enable_non_ssl_port = false
  minimum_tls_version = "1.2"
}
```

## Verification

```sh
`az redis show --name <name> --resource-group <rg> \
  --query '[enableNonSslPort, minimumTlsVersion]'`
must return `[false, "1.2"]`.
```

## References

**PCI-DSS**
  - `Req-4.1`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**Source**
  - [`catalog/SEC-AZURE-REDIS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-REDIS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-REDIS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-REDIS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-REDIS-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
