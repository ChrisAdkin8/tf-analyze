# ⚠️ STK-AZURE-NSG-FLOWLOG-001 — Azure NSG missing flow log resource

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **Azure NSG missing flow log resource.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_absent`** on `azurerm_network_watcher_flow_log` — _the corpus is missing a resource type we expected to find given other resources present._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-NSG-FLOWLOG-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add an `azurerm_network_watcher_flow_log` resource for every NSG:

    resource "azurerm_network_watcher_flow_log" "nsg" {
      network_watcher_name = azurerm_network_watcher.main.name
      resource_group_name  = azurerm_resource_group.main.name
      name                 = "nsg-flow-log"

      network_security_group_id = azurerm_network_security_group.main.id
      storage_account_id        = azurerm_storage_account.flow_logs.id
      enabled                   = true

      retention_policy {
        enabled = true
        days    = 90
      }

      traffic_analytics {
        enabled               = true
        workspace_id          = azurerm_log_analytics_workspace.main.workspace_id
        workspace_region      = azurerm_log_analytics_workspace.main.location
        workspace_resource_id = azurerm_log_analytics_workspace.main.id
        interval_in_minutes   = 10
      }
    }

NSG flow logs are the Azure equivalent of AWS VPC flow logs — the primary
source of network-layer evidence for post-incident investigation. Without
them, lateral movement and data exfiltration within a subnet are invisible.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_network_watcher_flow_log" "example" {
  name                      = "example"
  resource_group_name       = azurerm_resource_group.example.name
  network_watcher_name      = azurerm_network_watcher.example.name
  network_security_group_id = azurerm_network_security_group.example.id
  storage_account_id        = azurerm_storage_account.logs.id
  enabled                   = true
  retention_policy {
    enabled = true
    days    = 30
  }
}
```

## Verification

In the Azure portal: Network Watcher → Flow logs → confirm all NSGs have
an active flow log. Or:
`az network watcher flow-log list --location <region>`

## References

**CIS Benchmark**
  - `CIS 6.5`

**Source**
  - [`catalog/STK-AZURE-NSG-FLOWLOG-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-NSG-FLOWLOG-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-NSG-FLOWLOG-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-NSG-FLOWLOG-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-NSG-FLOWLOG-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
