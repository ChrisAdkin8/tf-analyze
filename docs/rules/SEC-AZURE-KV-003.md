---
title: "SEC-AZURE-KV-003 — Azure Key Vault key missing rotation policy"
description: "tf-analyze rule SEC-AZURE-KV-003 (MEDIUM · security): Azure Key Vault key missing rotation policy"
keywords: "security, medium, terraform, iac, azure, cis-8.6, mitre-T1098.001, d3-ch, nist-csf-pr.ac-1, nist-800-53-ia-5, nist-800-53-sc-12, csa-ccm-cek-09"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-KV-003 \u2014 Azure Key Vault key missing rotation policy",
  "description": "Add a rotation policy to every Key Vault key:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-KV-003/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-KV-003/"
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
  "keywords": "security, medium, terraform, CIS 8.6, MITRE T1098.001, D3-CH",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-AZURE-KV-003 — Azure Key Vault key missing rotation policy

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-KV-003" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-KV-003" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-KV-003 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure Key Vault key missing rotation policy.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_key_vault_key` (`rotation_policy.automatic.time_before_expiry`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_key_vault_key` without a `rotation_policy { automatic {} }`
block. The key material never rotates — a compromised key can decrypt
all data encrypted with it, past and future, until the key is
manually rotated. Equivalent to GCP `STK-GCP-KMS-001` (KMS rotation
period missing) and AWS `SEC-AWS-KMS-001` (enable_key_rotation).

## Why it likely fired

`azurerm_key_vault_key` without a `rotation_policy { automatic {} }`
block. The key material never rotates — a compromised key can decrypt
all data encrypted with it, past and future, until the key is
manually rotated. Equivalent to GCP `STK-GCP-KMS-001` (KMS rotation
period missing) and AWS `SEC-AWS-KMS-001` (enable_key_rotation).

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-KV-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a rotation policy to every Key Vault key:

    resource "azurerm_key_vault_key" "app" {
      name         = "app-key"
      key_vault_id = azurerm_key_vault.app.id
      key_type     = "RSA"
      key_size     = 2048
      key_opts     = ["decrypt", "encrypt", "sign", "verify"]

      rotation_policy {
        automatic {
          time_before_expiry = "P30D"  # rotate 30 days before expiry
        }
        expire_after         = "P90D"  # 90-day key lifetime
        notify_before_expiry = "P29D"
      }
    }

`time_before_expiry` uses ISO 8601 duration format (P30D = 30 days).
Set the key lifetime (`expire_after`) to ≤ 90 days for CIS compliance.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_key_vault_key" "example" {
  name         = "example"
  key_vault_id = azurerm_key_vault.example.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "sign", "verify"]
  rotation_policy {
    automatic {
      time_before_expiry = "P30D"
    }
    expire_after         = "P90D"
    notify_before_expiry = "P29D"
  }
}
```

## Verification

```sh
`az keyvault key show --vault-name <vault> --name <key> \
  --query 'attributes.{Expires:expires,Created:created}'`
Confirm a rotation policy exists in the Azure Portal:
Key Vault → Keys → <key> → Rotation policy.
```

## References

**CIS Benchmark**
  - `CIS 8.6`

**MITRE ATT&CK**
  - [`T1098.001`](https://attack.mitre.org/techniques/T1098/001/)

**MITRE D3FEND**
  - [`D3-CH`](https://d3fend.mitre.org/technique/D3-CH/)

**NIST CSF 2.0**
  - [`PR.AC-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`IA-5`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ia-5)
  - [`SC-12`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-12)

**CSA CCM v4**
  - [`CEK-09`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AZURE-KV-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-KV-003.yaml) — canonical YAML

## Family

See also rules in the `SEC-AZURE-KV-*` family:

- [`SEC-AZURE-KV-001`](./SEC-AZURE-KV-001.md) — Azure Key Vault missing purge protection or soft delete
- [`SEC-AZURE-KV-002`](./SEC-AZURE-KV-002.md) — Key Vault missing network ACL deny-by-default

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-KV-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-KV-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-KV-003
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
