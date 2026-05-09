# ⚠️ SEC-AZURE-LOGGING-001 — Azure Key Vault missing diagnostic settings

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Azure Key Vault missing diagnostic settings.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_absent`** on `azurerm_monitor_diagnostic_setting` — _the corpus is missing a resource type we expected to find given other resources present._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-LOGGING-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add `azurerm_monitor_diagnostic_setting` targeting the Key Vault with
`AuditEvent` logs enabled and at minimum a `log_analytics_workspace_id`
destination. Without this, secret access and modification events are
unlogged.

    resource "azurerm_monitor_diagnostic_setting" "kv" {
      name                       = "kv-diagnostics"
      target_resource_id         = azurerm_key_vault.example.id
      log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id

      enabled_log {
        category = "AuditEvent"
      }

      metric {
        category = "AllMetrics"
        enabled  = true
      }
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_monitor_diagnostic_setting" "kv" {
  name                       = "kv-diagnostics"
  target_resource_id         = azurerm_key_vault.example.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id
  enabled_log { category = "AuditEvent" }
  metric {
    category = "AllMetrics"
    enabled  = true
  }
}
```

## Verification

After applying, confirm with:

    az monitor diagnostic-settings list --resource <kv-id>

The response should be a non-empty list with `AuditEvent` enabled.

## References

**CIS Benchmark**
  - `CIS 8.7`

**PCI-DSS**
  - `Req-10.2`

**SOC 2 Trust Services Criteria**
  - `CC7.2`

**MITRE ATT&CK**
  - [`T1562.008`](https://attack.mitre.org/techniques/T1562/008/)

**Source**
  - [`catalog/SEC-AZURE-LOGGING-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-LOGGING-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-LOGGING-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-LOGGING-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-LOGGING-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
