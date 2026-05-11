---
title: "SEC-AZURE-REDIS-001 — Azure Redis Cache allows non-TLS connections"
description: "tf-analyze rule SEC-AZURE-REDIS-001 (HIGH · security): Azure Redis Cache allows non-TLS connections"
keywords: "security, high, terraform, iac, azure, mitre-T1040, mitre-T1071.001, cwe-319, d3-ei, nist-csf-pr.ds-2, nist-800-53-sc-8, nist-800-53-sc-8-1, csa-ccm-cek-06"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-REDIS-001 \u2014 Azure Redis Cache allows non-TLS connections",
  "description": "Disable the non-SSL port and enforce TLS 1.2:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-REDIS-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-REDIS-001/"
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
  "keywords": "security, high, terraform, MITRE T1040, MITRE T1071.001, CWE-319, D3-EI",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AZURE-REDIS-001 — Azure Redis Cache allows non-TLS connections

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-REDIS-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-REDIS-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-REDIS-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure Redis Cache allows non-TLS connections.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `azurerm_redis_cache` (`enable_non_ssl_port`) matching `/^true$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `azurerm_redis_cache` has `enable_non_ssl_port = true`. This opens
port 6379 for unencrypted Redis connections. Cache data — which often
includes session tokens, application state, and materialised query
results — is transmitted in cleartext over the network.
2. **`resource_arg`** on `azurerm_redis_cache` (`minimum_tls_version`) — _the resource declares the named attribute, but its value matches the rule's pattern._
  `azurerm_redis_cache` has `minimum_tls_version` below 1.2 or absent.
TLS 1.0 and 1.1 are vulnerable to POODLE, BEAST, and related attacks.
Require TLS 1.2 as the minimum.

## Why it likely fired

`azurerm_redis_cache` has `enable_non_ssl_port = true`. This opens
port 6379 for unencrypted Redis connections. Cache data — which often
includes session tokens, application state, and materialised query
results — is transmitted in cleartext over the network.

`azurerm_redis_cache` has `minimum_tls_version` below 1.2 or absent.
TLS 1.0 and 1.1 are vulnerable to POODLE, BEAST, and related attacks.
Require TLS 1.2 as the minimum.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-REDIS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Disable the non-SSL port and enforce TLS 1.2:

    resource "azurerm_redis_cache" "main" {
      # ...
      enable_non_ssl_port = false
      minimum_tls_version = "1.2"
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_redis_cache" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  capacity            = 1
  family              = "C"
  sku_name            = "Standard"
  enable_non_ssl_port = false
  minimum_tls_version = "1.2"
}
```

## Verification

```sh
`az redis show --name <name> --resource-group <rg> \
  --query '[enableNonSslPort, minimumTlsVersion]'`
must return `[false, "1.2"]`.
```

## References

**PCI-DSS**
  - `Req-4.1`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**MITRE ATT&CK**
  - [`T1040`](https://attack.mitre.org/techniques/T1040/)
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
  - [`catalog/SEC-AZURE-REDIS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-REDIS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-REDIS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-REDIS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-REDIS-001
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
