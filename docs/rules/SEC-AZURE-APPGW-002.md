---
title: "SEC-AZURE-APPGW-002 — Azure Application Gateway uses weak TLS policy"
description: "tf-analyze rule SEC-AZURE-APPGW-002 (HIGH · security): Azure Application Gateway uses weak TLS policy"
keywords: "security, high, terraform, iac, azure, cis-5.1, mitre-T1040, mitre-T1557, cwe-326, cwe-327, d3-et, nist-csf-pr.ds-2, nist-800-53-sc-8, nist-800-53-sc-13, csa-ccm-dsi-03"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-APPGW-002 \u2014 Azure Application Gateway uses weak TLS policy",
  "description": "Set `min_protocol_version = \"TLSv1_2\"` (or `\"TLSv1_3\"` if supported by\nthe App Gateway tier) and pin a modern predefined policy or a\nhand-curated `policy_type = \"Custom\"`:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-APPGW-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-APPGW-002/"
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
  "keywords": "security, high, terraform, CIS 5.1, MITRE T1040, MITRE T1557, CWE-326, CWE-327, D3-ET",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AZURE-APPGW-002 — Azure Application Gateway uses weak TLS policy

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-APPGW-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-APPGW-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-APPGW-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure Application Gateway uses weak TLS policy.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_body_contains`** on `azurerm_application_gateway` matching `/min_protocol_version\s*=\s*"(TLSv1_0|TLSv1_1)"/` — _the resource body matches a regex inside the block._
  Application Gateway `ssl_policy.min_protocol_version` permits
TLS 1.0 or TLS 1.1. Both are deprecated by the IETF and forbidden
by PCI-DSS v4.0 and FedRAMP. Modern HTTPS endpoints must require
TLS 1.2 or higher.
2. **`resource_body_contains`** on `azurerm_application_gateway` matching `/policy_name\s*=\s*"AppGwSslPolicy20150501"/` — _the resource body matches a regex inside the block._
  Application Gateway uses the legacy predefined SSL policy
`AppGwSslPolicy20150501`, which permits TLS 1.0 and weak ciphers.

## Why it likely fired

Application Gateway `ssl_policy.min_protocol_version` permits
TLS 1.0 or TLS 1.1. Both are deprecated by the IETF and forbidden
by PCI-DSS v4.0 and FedRAMP. Modern HTTPS endpoints must require
TLS 1.2 or higher.

Application Gateway uses the legacy predefined SSL policy
`AppGwSslPolicy20150501`, which permits TLS 1.0 and weak ciphers.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-APPGW-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `min_protocol_version = "TLSv1_2"` (or `"TLSv1_3"` if supported by
the App Gateway tier) and pin a modern predefined policy or a
hand-curated `policy_type = "Custom"`:

    resource "azurerm_application_gateway" "main" {
      # ...
      ssl_policy {
        policy_type          = "Predefined"
        policy_name          = "AppGwSslPolicy20220101S"
        min_protocol_version = "TLSv1_2"
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
    name     = "Standard_v2"
    tier     = "Standard_v2"
    capacity = 2
  }
  ssl_policy {
    policy_type          = "Predefined"
    policy_name          = "AppGwSslPolicy20220101S"
    min_protocol_version = "TLSv1_2"
  }
}
```

_Tightening the TLS policy may break ancient clients (Win XP IE, legacy embedded devices) that cannot negotiate TLS 1.2._

## Verification

```sh
`az network application-gateway ssl-policy show --gateway-name <name> \
  --resource-group <rg> --query minProtocolVersion` must return
`TLSv1_2` or `TLSv1_3`.
```

## References

**CIS Benchmark**
  - `CIS 5.1`

**PCI-DSS**
  - `Req-4.1`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**MITRE ATT&CK**
  - [`T1040`](https://attack.mitre.org/techniques/T1040/)
  - [`T1557`](https://attack.mitre.org/techniques/T1557/)

**CWE**
  - [`CWE-326`](https://cwe.mitre.org/data/definitions/326.html)
  - [`CWE-327`](https://cwe.mitre.org/data/definitions/327.html)

**MITRE D3FEND**
  - [`D3-ET`](https://d3fend.mitre.org/technique/D3-ET/)

**NIST CSF 2.0**
  - [`PR.DS-2`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-8`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-8)
  - [`SC-13`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-13)

**CSA CCM v4**
  - [`DSI-03`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AZURE-APPGW-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-APPGW-002.yaml) — canonical YAML

## Family

See also rules in the `SEC-AZURE-APPGW-*` family:

- [`SEC-AZURE-APPGW-001`](./SEC-AZURE-APPGW-001.md) — Azure Application Gateway has no WAF policy attached

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-APPGW-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-APPGW-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-APPGW-002
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
