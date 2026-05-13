---
title: "SEC-AZURE-APPGW-001 — Azure Application Gateway has no WAF policy attached"
description: "tf-analyze rule SEC-AZURE-APPGW-001 (HIGH · security): Azure Application Gateway has no WAF policy attached"
keywords: "security, high, terraform, iac, azure, cis-6.5, mitre-T1190, cwe-693, d3-waf, nist-csf-pr.pt-4, nist-800-53-sc-7, nist-800-53-si-4, csa-ccm-ais-04"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-APPGW-001 \u2014 Azure Application Gateway has no WAF policy attached",
  "description": "Attach an `azurerm_web_application_firewall_policy` to the gateway\nand enable the OWASP managed ruleset in Prevention mode:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-APPGW-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-APPGW-001/"
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
  "keywords": "security, high, terraform, CIS 6.5, MITRE T1190, CWE-693, D3-WAF",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AZURE-APPGW-001 — Azure Application Gateway has no WAF policy attached

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-APPGW-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-APPGW-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-APPGW-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure Application Gateway has no WAF policy attached.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_application_gateway` (`firewall_policy_id`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_application_gateway` has no `firewall_policy_id` and no
`waf_configuration` block. The gateway forwards every HTTP request
directly to the backend without inspection. Common attacks
(SQLi, XSS, path traversal, OWASP-Top-10 patterns) reach the
origin unfiltered.
2. **`resource_missing_arg`** on `azurerm_web_application_firewall_policy` (`managed_rules`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_web_application_firewall_policy` has no `managed_rules`
block — the policy exists but has no signature set attached, so
no requests are inspected.

## Why it likely fired

`azurerm_application_gateway` has no `firewall_policy_id` and no
`waf_configuration` block. The gateway forwards every HTTP request
directly to the backend without inspection. Common attacks
(SQLi, XSS, path traversal, OWASP-Top-10 patterns) reach the
origin unfiltered.

`azurerm_web_application_firewall_policy` has no `managed_rules`
block — the policy exists but has no signature set attached, so
no requests are inspected.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-APPGW-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Attach an `azurerm_web_application_firewall_policy` to the gateway
and enable the OWASP managed ruleset in Prevention mode:

    resource "azurerm_web_application_firewall_policy" "waf" {
      name                = "appgw-waf"
      resource_group_name = azurerm_resource_group.main.name
      location            = azurerm_resource_group.main.location
      policy_settings { mode = "Prevention" }
      managed_rules {
        managed_rule_set {
          type    = "OWASP"
          version = "3.2"
        }
      }
    }

    resource "azurerm_application_gateway" "main" {
      # ...
      firewall_policy_id = azurerm_web_application_firewall_policy.waf.id
      sku {
        name = "WAF_v2"
        tier = "WAF_v2"
        capacity = 2
      }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_application_gateway" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku {
    name     = "WAF_v2"
    tier     = "WAF_v2"
    capacity = 2
  }
  firewall_policy_id = azurerm_web_application_firewall_policy.example.id
}
```

_Switching SKU from Standard_v2 to WAF_v2 is in-place; attaching a Prevention-mode policy may block legitimate traffic if rules are not first tuned in Detection mode._

## Verification

```sh
`az network application-gateway show --name <name> --resource-group <rg> \
  --query 'firewallPolicy.id'` must return a non-null policy ID, and
the gateway SKU must be `WAF_v2`.
```

## References

**CIS Benchmark**
  - `CIS 6.5`

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
  - [`SI-4`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=si-4)

**CSA CCM v4**
  - [`AIS-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AZURE-APPGW-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-APPGW-001.yaml) — canonical YAML

## Family

See also rules in the `SEC-AZURE-APPGW-*` family:

- [`SEC-AZURE-APPGW-002`](./SEC-AZURE-APPGW-002.md) — Azure Application Gateway uses weak TLS policy

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-APPGW-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-APPGW-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-APPGW-001
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
