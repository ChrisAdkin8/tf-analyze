---
title: "SEC-AZURE-WEBAPP-002 — App Service / Function App HTTPS not enforced"
description: "tf-analyze rule SEC-AZURE-WEBAPP-002 (HIGH · security): App Service / Function App HTTPS not enforced"
keywords: "security, high, terraform, iac, azure, cis-9.2, mitre-T1071.001, cwe-319, d3-ei, nist-csf-pr.ds-2, nist-800-53-sc-8, nist-800-53-sc-8-1, csa-ccm-cek-06"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-WEBAPP-002 \u2014 App Service / Function App HTTPS not enforced",
  "description": "Set `https_only = true` on every App Service and Function App:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-WEBAPP-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-WEBAPP-002/"
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
  "keywords": "security, high, terraform, CIS 9.2, MITRE T1071.001, CWE-319, D3-EI",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AZURE-WEBAPP-002 — App Service / Function App HTTPS not enforced

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-WEBAPP-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-WEBAPP-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-WEBAPP-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

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

**MITRE ATT&CK**
  - [`T1071.001`](https://attack.mitre.org/techniques/T1071/001/)

**CWE**
  - [`CWE-319`](https://cwe.mitre.org/data/definitions/319.html)

**MITRE D3FEND**
  - [`D3-EI`](https://d3fend.mitre.org/technique/D3-EI/)

**NIST CSF 2.0**
  - [`PR.DS-2`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-8`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-8)
  - [`SC-8(1)`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-8-1)

**CSA CCM v4**
  - [`CEK-06`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AZURE-WEBAPP-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-WEBAPP-002.yaml) — canonical YAML

## Family

See also rules in the `SEC-AZURE-WEBAPP-*` family:

- [`SEC-AZURE-WEBAPP-001`](./SEC-AZURE-WEBAPP-001.md) — Azure App Service / Function App missing IP access restrictions

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
