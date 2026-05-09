# ⚠️ SEC-AZURE-WEBAPP-002 — App Service / Function App HTTPS not enforced

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **App Service / Function App HTTPS not enforced.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_linux_web_app` (`https_only`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_linux_web_app` without `https_only = true`. HTTP requests
are accepted alongside HTTPS, enabling cleartext credential harvest.
2. **`hcl_attr`** on `azurerm_linux_web_app` (`https_only`) not equal to `True` — _an attribute value differs from the expected literal._
3. **`resource_missing_arg`** on `azurerm_windows_web_app` (`https_only`) — _the resource is missing a required attribute (or nested attribute path)._
4. **`hcl_attr`** on `azurerm_windows_web_app` (`https_only`) not equal to `True` — _an attribute value differs from the expected literal._
5. **`resource_missing_arg`** on `azurerm_linux_function_app` (`https_only`) — _the resource is missing a required attribute (or nested attribute path)._
6. **`hcl_attr`** on `azurerm_linux_function_app` (`https_only`) not equal to `True` — _an attribute value differs from the expected literal._
7. **`resource_missing_arg`** on `azurerm_windows_function_app` (`https_only`) — _the resource is missing a required attribute (or nested attribute path)._
8. **`hcl_attr`** on `azurerm_windows_function_app` (`https_only`) not equal to `True` — _an attribute value differs from the expected literal._

## Why it likely fired

`azurerm_linux_web_app` without `https_only = true`. HTTP requests
are accepted alongside HTTPS, enabling cleartext credential harvest.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-WEBAPP-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `https_only = true` on every App Service and Function App:

    resource "azurerm_linux_web_app" "app" {
      name            = "app"
      https_only      = true
      # ...
    }

This causes Azure App Service to redirect all HTTP requests to HTTPS
(301 Permanent Redirect) before they reach the application code.
Without this flag, HTTP traffic is accepted — credentials and session
tokens cross the network in plaintext.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id
  https_only          = true
  site_config {}
}
```

## Verification

```sh
`az webapp show --name <name> --resource-group <rg> \
  --query 'httpsOnly'`
must return `true`.
```

## References

**CIS Benchmark**
  - `CIS 9.2`

**Source**
  - [`catalog/SEC-AZURE-WEBAPP-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-WEBAPP-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-WEBAPP-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-WEBAPP-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-WEBAPP-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
