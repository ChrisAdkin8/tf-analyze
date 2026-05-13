---
title: "SEC-AZURE-APIM-002 — Azure API Management product without rate-limit policy"
description: "tf-analyze rule SEC-AZURE-APIM-002 (MEDIUM · security): Azure API Management product without rate-limit policy"
keywords: "security, medium, terraform, iac, azure, mitre-T1498, cwe-770, nist-csf-pr.pt-4, nist-800-53-sc-5"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-APIM-002 \u2014 Azure API Management product without rate-limit policy",
  "description": "Attach a rate-limit / quota policy to the product:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-APIM-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-APIM-002/"
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
  "keywords": "security, medium, terraform, MITRE T1498, CWE-770",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-AZURE-APIM-002 — Azure API Management product without rate-limit policy

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-APIM-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-APIM-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-APIM-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure API Management product without rate-limit policy.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_absent`** on `azurerm_api_management_product_policy` — _the corpus is missing a resource type we expected to find given other resources present._
  `azurerm_api_management_product` exists but no
`azurerm_api_management_product_policy` is bound. Subscribers
can call APIs without rate limits — abuse traffic, scraping,
and DDoS reach the backend at full bore.

## Why it likely fired

`azurerm_api_management_product` exists but no
`azurerm_api_management_product_policy` is bound. Subscribers
can call APIs without rate limits — abuse traffic, scraping,
and DDoS reach the backend at full bore.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-APIM-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Attach a rate-limit / quota policy to the product:

    resource "azurerm_api_management_product_policy" "main" {
      product_id          = azurerm_api_management_product.main.product_id
      api_management_name = azurerm_api_management.main.name
      resource_group_name = azurerm_resource_group.main.name
      xml_content = <<XML
        <policies>
          <inbound>
            <rate-limit-by-key calls="100" renewal-period="60"
                               counter-key="@(context.Subscription.Key)" />
            <quota-by-key calls="100000" renewal-period="2592000"
                          counter-key="@(context.Subscription.Key)" />
            <base />
          </inbound>
        </policies>
      XML
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_api_management_product_policy" "example" {
  product_id          = azurerm_api_management_product.example.product_id
  api_management_name = azurerm_api_management.example.name
  resource_group_name = azurerm_resource_group.example.name
  xml_content         = "<policies><inbound><rate-limit-by-key calls=\"100\" renewal-period=\"60\" counter-key=\"@(context.Subscription.Key)\" /><base /></inbound></policies>"
}
```

## Verification

```sh
`az apim product policy show --service-name <s> --product-id <p> -g <rg>`
must contain a `<rate-limit>` or `<quota>` element.
```

## References

**MITRE ATT&CK**
  - [`T1498`](https://attack.mitre.org/techniques/T1498/)

**CWE**
  - [`CWE-770`](https://cwe.mitre.org/data/definitions/770.html)

**NIST CSF 2.0**
  - [`PR.PT-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-5`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-5)

**Source**
  - [`catalog/SEC-AZURE-APIM-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-APIM-002.yaml) — canonical YAML

## Family

See also rules in the `SEC-AZURE-APIM-*` family:

- [`SEC-AZURE-APIM-001`](./SEC-AZURE-APIM-001.md) — Azure API Management missing diagnostic settings

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-APIM-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-APIM-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-APIM-002
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
