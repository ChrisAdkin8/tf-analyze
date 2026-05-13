---
title: "STK-AZURE-FUNCTION-AUTH-001 — Azure Function App missing platform-level authentication"
description: "tf-analyze rule STK-AZURE-FUNCTION-AUTH-001 (HIGH · stack): Azure Function App missing platform-level authentication"
keywords: "stack, high, terraform, iac, azure, mitre-T1190, cwe-287, d3-uac, nist-csf-pr.ac-1, nist-800-53-ac-3"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AZURE-FUNCTION-AUTH-001 \u2014 Azure Function App missing platform-level authentication",
  "description": "Enable `auth_settings_v2` and require Microsoft Entra ID:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-FUNCTION-AUTH-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-FUNCTION-AUTH-001/"
  },
  "author": {
    "@type": "Organization",
    "name": "tf-analyze"
  },
  "publisher": {
    "@type": "Organization",
    "name": "tf-analyze",
    "url": "https://chrisadkin8.github.io/tf-analyze"
  },
  "keywords": "stack, high, terraform, MITRE T1190, CWE-287, D3-UAC",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-AZURE-FUNCTION-AUTH-001 — Azure Function App missing platform-level authentication

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AZURE-FUNCTION-AUTH-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-AZURE-FUNCTION-AUTH-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-AZURE-FUNCTION-AUTH-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure Function App missing platform-level authentication.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_linux_function_app` (`auth_settings_v2`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_linux_function_app` has no `auth_settings_v2`. HTTP-
triggered functions accept anonymous requests; only host-key
based auth (a query-string secret) gates access. Equivalent to
AWS Lambda Function URL with `AuthType: NONE`.
2. **`resource_missing_arg`** on `azurerm_windows_function_app` (`auth_settings_v2`) — _the resource is missing a required attribute (or nested attribute path)._
  Windows Function App missing platform-level auth

## Why it likely fired

`azurerm_linux_function_app` has no `auth_settings_v2`. HTTP-
triggered functions accept anonymous requests; only host-key
based auth (a query-string secret) gates access. Equivalent to
AWS Lambda Function URL with `AuthType: NONE`.

Windows Function App missing platform-level auth

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-FUNCTION-AUTH-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable `auth_settings_v2` and require Microsoft Entra ID:

    resource "azurerm_linux_function_app" "main" {
      # ...
      auth_settings_v2 {
        auth_enabled           = true
        require_authentication = true
        default_provider       = "AzureActiveDirectory"
        active_directory_v2 {
          client_id            = var.aad_client_id
          tenant_auth_endpoint = "https://login.microsoftonline.com/${var.tenant_id}/v2.0"
        }
        login {}
      }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_linux_function_app" "example" {
  name                       = "example"
  resource_group_name        = azurerm_resource_group.example.name
  location                   = azurerm_resource_group.example.location
  service_plan_id            = azurerm_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  site_config {}
  auth_settings_v2 {
    auth_enabled           = true
    require_authentication = true
    default_provider       = "AzureActiveDirectory"
    login {}
  }
}
```

## Verification

```sh
`az functionapp auth show -g <rg> -n <name> --query 'platform.enabled'`
must return `true`.
```

## References

**PCI-DSS**
  - `Req-7.1`

**SOC 2 Trust Services Criteria**
  - `CC6.3`

**MITRE ATT&CK**
  - [`T1190`](https://attack.mitre.org/techniques/T1190/)

**CWE**
  - [`CWE-287`](https://cwe.mitre.org/data/definitions/287.html)

**MITRE D3FEND**
  - [`D3-UAC`](https://d3fend.mitre.org/technique/D3-UAC/)

**NIST CSF 2.0**
  - [`PR.AC-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AC-3`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-3)

**Source**
  - [`catalog/STK-AZURE-FUNCTION-AUTH-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-FUNCTION-AUTH-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-FUNCTION-AUTH-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-FUNCTION-AUTH-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-FUNCTION-AUTH-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
{% if site.giscus.enabled %}
---

## Discussion

<script src="https://giscus.app/client.js"
        data-repo="{{ site.giscus.repo }}"
        data-repo-id="{{ site.giscus.repo_id }}"
        data-category="{{ site.giscus.category }}"
        data-category-id="{{ site.giscus.category_id }}"
        data-mapping="{{ site.giscus.mapping }}"
        data-strict="0"
        data-reactions-enabled="{{ site.giscus.reactions }}"
        data-emit-metadata="{{ site.giscus.emit_metadata }}"
        data-input-position="{{ site.giscus.input_position }}"
        data-theme="{{ site.giscus.theme }}"
        data-lang="en"
        crossorigin="anonymous"
        async>
</script>

{% endif %}
