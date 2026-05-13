---
title: "SEC-AZURE-STORAGE-003 — Azure storage account not using customer-managed key encryption"
description: "tf-analyze rule SEC-AZURE-STORAGE-003 (MEDIUM · security): Azure storage account not using customer-managed key encryption"
keywords: "security, medium, terraform, iac, azure, cis-3.10, mitre-T1530, cwe-311, d3-ear, nist-csf-pr.ds-1, nist-800-53-sc-13, nist-800-53-sc-28, csa-ccm-cek-03"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-STORAGE-003 \u2014 Azure storage account not using customer-managed key encryption",
  "description": "Either configure a `customer_managed_key` block inline, or attach an\n`azurerm_storage_account_customer_managed_key` resource:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-STORAGE-003/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-STORAGE-003/"
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
  "keywords": "security, medium, terraform, CIS 3.10, MITRE T1530, CWE-311, D3-EAR",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-AZURE-STORAGE-003 — Azure storage account not using customer-managed key encryption

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-STORAGE-003" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-STORAGE-003" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-STORAGE-003 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure storage account not using customer-managed key encryption.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_storage_account` (`customer_managed_key`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_storage_account` has no `customer_managed_key` block and no
paired `azurerm_storage_account_customer_managed_key` resource. Without
a CMK, blob/file/queue/table data is encrypted with a Microsoft-managed
key that cannot be revoked, audited independently, or rotated on a
custom schedule. CMK is required for PCI-DSS Req-3.4 and CIS 3.10.

## Why it likely fired

`azurerm_storage_account` has no `customer_managed_key` block and no
paired `azurerm_storage_account_customer_managed_key` resource. Without
a CMK, blob/file/queue/table data is encrypted with a Microsoft-managed
key that cannot be revoked, audited independently, or rotated on a
custom schedule. CMK is required for PCI-DSS Req-3.4 and CIS 3.10.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-STORAGE-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Either configure a `customer_managed_key` block inline, or attach an
`azurerm_storage_account_customer_managed_key` resource:

    resource "azurerm_storage_account" "main" {
      # ...
      identity { type = "SystemAssigned" }
      customer_managed_key {
        key_vault_key_id = azurerm_key_vault_key.sa.id
      }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_storage_account" "example" {
  name                     = "example"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  identity { type = "SystemAssigned" }
  customer_managed_key {
    key_vault_key_id = azurerm_key_vault_key.example.id
  }
}
```

_Switching to CMK re-encrypts in place; storage account remains online but plan/apply is required._

## Verification

```sh
`az storage account show --name <name> --query encryption.keySource`
must return `"Microsoft.Keyvault"`.
```

## References

**CIS Benchmark**
  - `CIS 3.10`

**PCI-DSS**
  - `Req-3.4`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**MITRE ATT&CK**
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)

**CWE**
  - [`CWE-311`](https://cwe.mitre.org/data/definitions/311.html)

**MITRE D3FEND**
  - [`D3-EAR`](https://d3fend.mitre.org/technique/D3-EAR/)

**NIST CSF 2.0**
  - [`PR.DS-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-13`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-13)
  - [`SC-28`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-28)

**CSA CCM v4**
  - [`CEK-03`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AZURE-STORAGE-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-STORAGE-003.yaml) — canonical YAML

## Family

See also rules in the `SEC-AZURE-STORAGE-*` family:

- [`SEC-AZURE-STORAGE-001`](./SEC-AZURE-STORAGE-001.md) — Azure storage account allows non-HTTPS traffic
- [`SEC-AZURE-STORAGE-002`](./SEC-AZURE-STORAGE-002.md) — Azure storage account allows public blob access
- [`SEC-AZURE-STORAGE-004`](./SEC-AZURE-STORAGE-004.md) — Azure storage account missing diagnostic logging

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-STORAGE-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-STORAGE-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-STORAGE-003
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
