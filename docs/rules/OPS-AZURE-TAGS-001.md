# 💡 OPS-AZURE-TAGS-001 — Azure resource missing tags

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: ops](https://img.shields.io/badge/section-ops-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Azure resource missing tags.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_resource_group` (`tags`) — _the resource is missing a required attribute (or nested attribute path)._
2. **`resource_missing_arg`** on `azurerm_storage_account` (`tags`) — _the resource is missing a required attribute (or nested attribute path)._
3. **`resource_missing_arg`** on `azurerm_kubernetes_cluster` (`tags`) — _the resource is missing a required attribute (or nested attribute path)._
4. **`resource_missing_arg`** on `azurerm_mssql_server` (`tags`) — _the resource is missing a required attribute (or nested attribute path)._
5. **`resource_missing_arg`** on `azurerm_virtual_machine` (`tags`) — _the resource is missing a required attribute (or nested attribute path)._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain OPS-AZURE-TAGS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a `tags` block with at minimum `environment`, `managed_by = "terraform"`,
and `project`. Use a `locals { common_tags = {...} }` pattern and merge with
`merge(local.common_tags, {...})` for resource-specific tags.

    locals {
      common_tags = {
        environment = var.environment
        managed_by  = "terraform"
        project     = var.project_name
      }
    }

    resource "azurerm_resource_group" "example" {
      # ...
      tags = local.common_tags
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_resource_group" "example" {
  # ... other arguments ...
  tags = {
    Environment = "prod"
    Owner       = "platform-team"
    Project     = "my-project"
  }
}
```

## Verification

Confirm in the Azure portal that the resource shows the expected tags, or run:

    az resource show --ids <resource-id> --query tags

## References

**Source**
  - [`catalog/OPS-AZURE-TAGS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/OPS-AZURE-TAGS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain OPS-AZURE-TAGS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore OPS-AZURE-TAGS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - OPS-AZURE-TAGS-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
