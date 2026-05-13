---
title: "SEC-AZURE-FRONTDOOR-001 — Azure Front Door profile missing WAF policy attachment"
description: "tf-analyze rule SEC-AZURE-FRONTDOOR-001 (HIGH · security): Azure Front Door profile missing WAF policy attachment"
keywords: "security, high, terraform, iac, azure, mitre-T1190, cwe-693, d3-waf, nist-csf-pr.pt-4, nist-800-53-sc-7, csa-ccm-ais-04"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-FRONTDOOR-001 \u2014 Azure Front Door profile missing WAF policy attachment",
  "description": "Provision a Front Door WAF policy in Prevention mode and attach it\nto the security_policy block:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-FRONTDOOR-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-FRONTDOOR-001/"
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
  "keywords": "security, high, terraform, MITRE T1190, CWE-693, D3-WAF",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AZURE-FRONTDOOR-001 — Azure Front Door profile missing WAF policy attachment

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-FRONTDOOR-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-FRONTDOOR-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-FRONTDOOR-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure Front Door profile missing WAF policy attachment.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_absent`** on `azurerm_cdn_frontdoor_firewall_policy` — _the corpus is missing a resource type we expected to find given other resources present._
  `azurerm_cdn_frontdoor_profile` exists but no
`azurerm_cdn_frontdoor_firewall_policy` is declared. Every HTTP
request flows directly to the origin without WAF inspection —
OWASP-Top-10 attacks (SQLi, XSS, path traversal) reach the
origin unfiltered.

## Why it likely fired

`azurerm_cdn_frontdoor_profile` exists but no
`azurerm_cdn_frontdoor_firewall_policy` is declared. Every HTTP
request flows directly to the origin without WAF inspection —
OWASP-Top-10 attacks (SQLi, XSS, path traversal) reach the
origin unfiltered.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-FRONTDOOR-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Provision a Front Door WAF policy in Prevention mode and attach it
to the security_policy block:

    resource "azurerm_cdn_frontdoor_firewall_policy" "waf" {
      name                = "fd-waf"
      resource_group_name = azurerm_resource_group.main.name
      sku_name            = "Premium_AzureFrontDoor"
      enabled             = true
      mode                = "Prevention"
      managed_rule { type = "Microsoft_DefaultRuleSet" version = "2.1" action = "Block" }
    }

    resource "azurerm_cdn_frontdoor_security_policy" "main" {
      name                     = "fd-security"
      cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.main.id
      security_policies {
        firewall {
          cdn_frontdoor_firewall_policy_id = azurerm_cdn_frontdoor_firewall_policy.waf.id
          association {
            domain { cdn_frontdoor_domain_id = azurerm_cdn_frontdoor_custom_domain.main.id }
            patterns_to_match = ["/*"]
          }
        }
      }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_cdn_frontdoor_firewall_policy" "example" {
  name                = "example-waf"
  resource_group_name = azurerm_resource_group.example.name
  sku_name            = "Premium_AzureFrontDoor"
  enabled             = true
  mode                = "Prevention"
  managed_rule {
    type    = "Microsoft_DefaultRuleSet"
    version = "2.1"
    action  = "Block"
  }
}
```

## Verification

```sh
`az afd security-policy list --profile-name <name> -g <rg>` must
return at least one security policy with a non-null `wafPolicy`.
```

## References

**PCI-DSS**
  - `Req-6.6`

**SOC 2 Trust Services Criteria**
  - `CC6.6`

**MITRE ATT&CK**
  - [`T1190`](https://attack.mitre.org/techniques/T1190/)

**CWE**
  - [`CWE-693`](https://cwe.mitre.org/data/definitions/693.html)

**MITRE D3FEND**
  - [`D3-WAF`](https://d3fend.mitre.org/technique/D3-WAF/)

**NIST CSF 2.0**
  - [`PR.PT-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-7`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-7)

**CSA CCM v4**
  - [`AIS-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AZURE-FRONTDOOR-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-FRONTDOOR-001.yaml) — canonical YAML

## Family

See also rules in the `SEC-AZURE-FRONTDOOR-*` family:

- [`SEC-AZURE-FRONTDOOR-002`](./SEC-AZURE-FRONTDOOR-002.md) — Azure Front Door custom domain accepts TLS < 1.2

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-FRONTDOOR-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-FRONTDOOR-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-FRONTDOOR-001
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
