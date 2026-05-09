# ⚠️ SEC-AZURE-STORAGE-001 — Azure storage account allows non-HTTPS traffic

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Azure storage account allows non-HTTPS traffic.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `azurerm_storage_account` (`enable_https_traffic_only`) matching `/^false$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
2. **`resource_arg`** on `azurerm_storage_account` (`https_only`) matching `/^false$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
3. **`resource_arg`** on `azurerm_storage_account` (`min_tls_version`) matching `/^(TLS1_0|TLS1_1)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-STORAGE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `https_only = true` (provider v3+) or `enable_https_traffic_only = true`
(provider v2). Also set `min_tls_version = "TLS1_2"`. Allowing HTTP exposes
storage account keys and SAS tokens in transit.

    resource "azurerm_storage_account" "example" {
      # ...
      https_only       = true
      min_tls_version  = "TLS1_2"
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_storage_account" "example" {
  # ... other arguments ...
  https_traffic_only_enabled = true
  min_tls_version            = "TLS1_2"
}
```

## Verification

After applying, confirm with:

    az storage account show --name <name> --query 'enableHttpsTrafficOnly'

The command should return `true`.

## References

**CIS Benchmark**
  - `CIS 3.1`

**Source**
  - [`catalog/SEC-AZURE-STORAGE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-STORAGE-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-STORAGE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-STORAGE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-STORAGE-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
