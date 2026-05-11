---
title: "SEC-AZURE-KV-002 — Key Vault missing network ACL deny-by-default"
description: "tf-analyze rule SEC-AZURE-KV-002 (HIGH · security): Key Vault missing network ACL deny-by-default"
keywords: "security, high, terraform, iac, azure, cis-8.5, mitre-T1530, mitre-T1133, nist-csf-pr.ds-1, nist-800-53-sc-13, nist-800-53-sc-28, csa-ccm-cek-03"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-KV-002 \u2014 Key Vault missing network ACL deny-by-default",
  "description": "Set the default action to `\"Deny\"` and enumerate the allowed CIDRs /\nVNet subnets explicitly:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-KV-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-KV-002/"
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
  "keywords": "security, high, terraform, CIS 8.5, MITRE T1530, MITRE T1133",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AZURE-KV-002 — Key Vault missing network ACL deny-by-default

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-KV-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-KV-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-KV-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Key Vault missing network ACL deny-by-default.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_key_vault` (`network_acls.default_action`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_key_vault` with no `network_acls` block. The default
network access is `"Allow"` — the vault endpoint accepts requests
from any IP. Any credential that can reach the vault over the public
internet can enumerate and read secrets.
2. **`hcl_attr`** on `azurerm_key_vault` (`network_acls.default_action`) not equal to `"Deny"` — _an attribute value differs from the expected literal._
  `network_acls.default_action` is set to `"Allow"`. All traffic is
permitted unless an explicit deny IP rule matches first.

## Why it likely fired

`azurerm_key_vault` with no `network_acls` block. The default
network access is `"Allow"` — the vault endpoint accepts requests
from any IP. Any credential that can reach the vault over the public
internet can enumerate and read secrets.

`network_acls.default_action` is set to `"Allow"`. All traffic is
permitted unless an explicit deny IP rule matches first.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-KV-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set the default action to `"Deny"` and enumerate the allowed CIDRs /
VNet subnets explicitly:

    resource "azurerm_key_vault" "app" {
      name = "kv-app"
      # ...

      network_acls {
        default_action             = "Deny"
        bypass                     = "AzureServices"
        ip_rules                   = ["203.0.113.0/24"]
        virtual_network_subnet_ids = [azurerm_subnet.app.id]
      }
    }

`bypass = "AzureServices"` allows diagnostic and monitoring services
that run in the Azure backbone to reach the vault — omitting it breaks
Key Vault audit logging.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_key_vault" "example" {
  # ... other arguments ...
  network_acls {
    default_action = "Deny"
    bypass         = ["AzureServices"]
    ip_rules       = []
  }
}
```

## Verification

```sh
`az keyvault show --name <name> --resource-group <rg> \
  --query 'properties.networkAcls.defaultAction'`
must return `"Deny"`.
```

## References

**CIS Benchmark**
  - `CIS 8.5`

**MITRE ATT&CK**
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)
  - [`T1133`](https://attack.mitre.org/techniques/T1133/)

**NIST CSF 2.0**
  - [`PR.DS-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-13`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-13)
  - [`SC-28`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-28)

**CSA CCM v4**
  - [`CEK-03`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AZURE-KV-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-KV-002.yaml) — canonical YAML

## Family

See also rules in the `SEC-AZURE-KV-*` family:

- [`SEC-AZURE-KV-001`](./SEC-AZURE-KV-001.md) — Azure Key Vault missing purge protection or soft delete
- [`SEC-AZURE-KV-003`](./SEC-AZURE-KV-003.md) — Azure Key Vault key missing rotation policy

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-KV-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-KV-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-KV-002
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
