# ⚠️ STK-AZURE-NSG-001 — Azure NSG rule open to the internet on sensitive ports

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **Azure NSG rule open to the internet on sensitive ports.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`grep`** matching `/source_address_prefix\s*=\s*"\*"/` — _a textual regex matched somewhere in the file._
2. **`grep`** matching `/source_address_prefix\s*=\s*"Internet"/` — _a textual regex matched somewhere in the file._
3. **`grep`** matching `/source_address_prefix\s*=\s*"0\.0\.0\.0/0"/` — _a textual regex matched somewhere in the file._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-NSG-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace `source_address_prefix = "*"` with a specific CIDR or Azure service
tag. For SSH/RDP, use Azure Bastion instead of opening ports to the internet.
For internal services, use VNet service tags (`VirtualNetwork`) rather than `*`.

    # Bad — any IP on the internet can reach this port
    source_address_prefix = "*"

    # Better — restrict to a known CIDR
    source_address_prefix = "10.0.0.0/8"

    # Best for management ports — use Azure Bastion and remove the rule
If port 22 or 3389 is involved, treat this as CRITICAL and remediate
immediately.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_network_security_rule" "example" {
  name                        = "allow-https"
  resource_group_name         = azurerm_resource_group.example.name
  network_security_group_name = azurerm_network_security_group.example.name
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "203.0.113.0/24"
  destination_address_prefix  = "*"
}
```

## Verification

After applying, confirm with:

    az network nsg rule list --nsg-name <nsg> --resource-group <rg> \
      --output table

No rules should have `*` or `Internet` as source with port 22 or 3389 as
destination.

## References

**CIS Benchmark**
  - `CIS 6.1`
  - `CIS 6.2`

**Source**
  - [`catalog/STK-AZURE-NSG-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-NSG-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-NSG-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-NSG-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-NSG-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
