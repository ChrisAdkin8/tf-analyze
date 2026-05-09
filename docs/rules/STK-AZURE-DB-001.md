# ⚠️ STK-AZURE-DB-001 — Azure MySQL/PostgreSQL server missing SSL enforcement

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Azure MySQL/PostgreSQL server missing SSL enforcement.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_mysql_server` (`ssl_enforcement_enabled`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_mysql_server` without `ssl_enforcement_enabled`. Client
connections can be made over plaintext, exposing credentials and
query results on the network.
2. **`hcl_attr`** on `azurerm_mysql_server` (`ssl_enforcement_enabled`) not equal to `True` — _an attribute value differs from the expected literal._
3. **`resource_missing_arg`** on `azurerm_postgresql_server` (`ssl_enforcement_enabled`) — _the resource is missing a required attribute (or nested attribute path)._
4. **`hcl_attr`** on `azurerm_postgresql_server` (`ssl_enforcement_enabled`) not equal to `True` — _an attribute value differs from the expected literal._

## Why it likely fired

`azurerm_mysql_server` without `ssl_enforcement_enabled`. Client
connections can be made over plaintext, exposing credentials and
query results on the network.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-DB-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `ssl_enforcement_enabled = true` on every MySQL and PostgreSQL
Single Server resource:

    resource "azurerm_mysql_server" "app" {
      ssl_enforcement_enabled          = true
      ssl_minimal_tls_version_enforced = "TLS1_2"
      # ...
    }

For Flexible Server (the preferred, non-deprecated resource), SSL is
enforced by default and controlled via `azurerm_mysql_flexible_server_configuration`
with the `require_secure_transport` parameter.

Equivalent to GCP `STK-GCP-CLOUDSQL-004` (require_ssl).

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_mysql_server" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku_name            = "B_Gen5_1"
  ssl_enforcement_enabled          = true
  ssl_minimal_tls_version_enforced = "TLS1_2"
}
```

## Verification

```sh
`az mysql server show --name <server> --resource-group <rg> \
  --query 'sslEnforcement'`
must return `"Enabled"`.
```

## References

**CIS Benchmark**
  - `CIS 4.3.1`

**Source**
  - [`catalog/STK-AZURE-DB-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-DB-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-DB-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-DB-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-DB-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
