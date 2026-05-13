---
title: "STK-AZURE-FUNCTION-002 — Azure Function App missing Application Insights instrumentation"
description: "tf-analyze rule STK-AZURE-FUNCTION-002 (MEDIUM · stack): Azure Function App missing Application Insights instrumentation"
keywords: "stack, medium, terraform, iac, azure, mitre-T1530, cwe-778, d3-iaa, nist-csf-de.cm-1, nist-csf-de.ae-3, nist-800-53-au-2, nist-800-53-au-12, csa-ccm-log-08"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AZURE-FUNCTION-002 \u2014 Azure Function App missing Application Insights instrumentation",
  "description": "Wire the function app to an App Insights instance:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-FUNCTION-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-FUNCTION-002/"
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
  "keywords": "stack, medium, terraform, MITRE T1530, CWE-778, D3-IAA",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# 💡 STK-AZURE-FUNCTION-002 — Azure Function App missing Application Insights instrumentation

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AZURE-FUNCTION-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-AZURE-FUNCTION-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-AZURE-FUNCTION-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure Function App missing Application Insights instrumentation.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_linux_function_app` (`site_config`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_linux_function_app` has no `site_config.application_insights_*`
arguments. Without App Insights, function invocations, dependencies,
and unhandled exceptions are not telemetered — incident response,
latency analysis, and cold-start tuning all blind.
2. **`resource_missing_arg`** on `azurerm_windows_function_app` (`site_config`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_windows_function_app` has no `site_config.application_insights_*`
arguments — same observability blind-spot as the Linux variant.

## Why it likely fired

`azurerm_linux_function_app` has no `site_config.application_insights_*`
arguments. Without App Insights, function invocations, dependencies,
and unhandled exceptions are not telemetered — incident response,
latency analysis, and cold-start tuning all blind.

`azurerm_windows_function_app` has no `site_config.application_insights_*`
arguments — same observability blind-spot as the Linux variant.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-FUNCTION-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Wire the function app to an App Insights instance:

    resource "azurerm_application_insights" "fn" {
      name                = "fn-insights"
      location            = azurerm_resource_group.main.location
      resource_group_name = azurerm_resource_group.main.name
      application_type    = "web"
    }

    resource "azurerm_linux_function_app" "main" {
      # ...
      site_config {
        application_insights_key               = azurerm_application_insights.fn.instrumentation_key
        application_insights_connection_string = azurerm_application_insights.fn.connection_string
      }
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_linux_function_app" "example" {
  name                       = "example"
  resource_group_name        = azurerm_resource_group.example.name
  location                   = azurerm_resource_group.example.location
  service_plan_id            = azurerm_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key

  site_config {
    application_insights_key               = azurerm_application_insights.example.instrumentation_key
    application_insights_connection_string = azurerm_application_insights.example.connection_string
  }
}
```

## Verification

```sh
`az functionapp config appsettings list --name <name> --resource-group <rg>` must
include `APPINSIGHTS_INSTRUMENTATIONKEY` (or
`APPLICATIONINSIGHTS_CONNECTION_STRING`) with a non-empty value.
```

## References

**SOC 2 Trust Services Criteria**
  - `CC7.2`

**MITRE ATT&CK**
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)

**CWE**
  - [`CWE-778`](https://cwe.mitre.org/data/definitions/778.html)

**MITRE D3FEND**
  - [`D3-IAA`](https://d3fend.mitre.org/technique/D3-IAA/)

**NIST CSF 2.0**
  - [`DE.CM-1`](https://www.nist.gov/cyberframework)
  - [`DE.AE-3`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AU-2`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=au-2)
  - [`AU-12`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=au-12)

**CSA CCM v4**
  - [`LOG-08`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/STK-AZURE-FUNCTION-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-FUNCTION-002.yaml) — canonical YAML

## Family

See also rules in the `STK-AZURE-FUNCTION-*` family:

- [`STK-AZURE-FUNCTION-001`](./STK-AZURE-FUNCTION-001.md) — Azure Function App uses end-of-life runtime

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-FUNCTION-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-FUNCTION-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-FUNCTION-002
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
