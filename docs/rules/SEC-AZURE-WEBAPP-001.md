---
title: "SEC-AZURE-WEBAPP-001 — Azure App Service / Function App missing IP access restrictions"
description: "tf-analyze rule SEC-AZURE-WEBAPP-001 (MEDIUM · security): Azure App Service / Function App missing IP access restrictions"
keywords: "security, medium, terraform, iac, azure, mitre-T1133, cwe-284, d3-iaa"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-WEBAPP-001 \u2014 Azure App Service / Function App missing IP access restrictions",
  "description": "Add `ip_restriction` and `scm_ip_restriction` blocks inside `site_config` to\nlimit access to known CIDRs or service tags. Without this, the web app\nmanagement plane is reachable from any IP.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-WEBAPP-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-WEBAPP-001/"
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
  "keywords": "security, medium, terraform, MITRE T1133, CWE-284, D3-IAA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-AZURE-WEBAPP-001 — Azure App Service / Function App missing IP access restrictions

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-WEBAPP-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-WEBAPP-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-WEBAPP-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure App Service / Function App missing IP access restrictions.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_app_service` (`site_config`) — _the resource is missing a required attribute (or nested attribute path)._
2. **`resource_missing_arg`** on `azurerm_linux_web_app` (`site_config`) — _the resource is missing a required attribute (or nested attribute path)._
3. **`resource_missing_arg`** on `azurerm_windows_web_app` (`site_config`) — _the resource is missing a required attribute (or nested attribute path)._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-WEBAPP-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add `ip_restriction` and `scm_ip_restriction` blocks inside `site_config` to
limit access to known CIDRs or service tags. Without this, the web app
management plane is reachable from any IP.

    resource "azurerm_linux_web_app" "example" {
      # ...
      site_config {
        ip_restriction {
          ip_address = "203.0.113.0/24"
          name       = "office-network"
          priority   = 100
          action     = "Allow"
        }
        scm_ip_restriction {
          ip_address = "203.0.113.0/24"
          name       = "office-network"
          priority   = 100
          action     = "Allow"
        }
      }
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id
  site_config {
    ip_restriction {
      ip_address = "203.0.113.0/24"
      name       = "allow-corporate"
      priority   = 100
      action     = "Allow"
    }
    scm_ip_restriction {
      ip_address = "203.0.113.0/24"
      name       = "allow-corporate"
      priority   = 100
      action     = "Allow"
    }
  }
}
```

## Verification

After applying, confirm with:

    az webapp show --name <name> --resource-group <rg> \
      --query siteConfig.ipSecurityRestrictions

The list should contain only expected CIDRs or service tags, not `Any`/`0.0.0.0/0`.

## References

**MITRE ATT&CK**
  - [`T1133`](https://attack.mitre.org/techniques/T1133/)

**CWE**
  - [`CWE-284`](https://cwe.mitre.org/data/definitions/284.html)

**MITRE D3FEND**
  - [`D3-IAA`](https://d3fend.mitre.org/technique/D3-IAA/)

**Source**
  - [`catalog/SEC-AZURE-WEBAPP-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-WEBAPP-001.yaml) — canonical YAML

## Family

See also rules in the `SEC-AZURE-WEBAPP-*` family:

- [`SEC-AZURE-WEBAPP-002`](./SEC-AZURE-WEBAPP-002.md) — App Service / Function App HTTPS not enforced

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-WEBAPP-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-WEBAPP-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-WEBAPP-001
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
