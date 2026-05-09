# ⚠️ SEC-AZURE-MONITOR-001 — Azure subscription missing activity log diagnostic setting

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **Azure subscription missing activity log diagnostic setting.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_absent`** on `azurerm_subscription_diagnostic_setting` — _the corpus is missing a resource type we expected to find given other resources present._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-MONITOR-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add an `azurerm_subscription_diagnostic_setting` to forward subscription
Activity Logs to a Log Analytics workspace or storage account:

    resource "azurerm_subscription_diagnostic_setting" "activity" {
      name               = "activity-log-to-law"
      target_resource_id = "/subscriptions/${var.subscription_id}"

      log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

      enabled_log {
        category = "Administrative"
      }
      enabled_log {
        category = "Security"
      }
      enabled_log {
        category = "Alert"
      }
      enabled_log {
        category = "Policy"
      }
    }

Without this, all Resource Manager API calls (create/delete/modify) age out
at the platform's 90-day retention with no long-term archive. Post-incident
investigations are blind beyond that window.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_subscription_diagnostic_setting" "activity" {
  name                       = "activity-to-law"
  target_resource_id         = "/subscriptions/${var.subscription_id}"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  enabled_log { category = "Administrative" }
  enabled_log { category = "Security" }
  enabled_log { category = "Alert" }
  enabled_log { category = "Policy" }
}
```

## Verification

```sh
`az monitor diagnostic-settings subscriptions list` must return at least one
setting with Log Analytics or storage sink. Re-run tf-analyze mode:verify-fixed.
```

## References

**CIS Benchmark**
  - `CIS 5.2.1`

**MITRE ATT&CK**
  - [`T1562.008`](https://attack.mitre.org/techniques/T1562/008/)

**Source**
  - [`catalog/SEC-AZURE-MONITOR-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-MONITOR-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-MONITOR-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-MONITOR-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-MONITOR-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
