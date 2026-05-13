---
title: "SEC-AZURE-KV-CERT-001 — Azure Key Vault certificate missing auto-renewal policy"
description: "tf-analyze rule SEC-AZURE-KV-CERT-001 (MEDIUM · security): Azure Key Vault certificate missing auto-renewal policy"
keywords: "security, medium, terraform, iac, azure, mitre-T1552.004, cwe-321, d3-cr, nist-csf-pr.ds-2, nist-800-53-sc-12"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-KV-CERT-001 \u2014 Azure Key Vault certificate missing auto-renewal policy",
  "description": "Embed a renewal policy that issues a new version some days before\nexpiry:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-KV-CERT-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-KV-CERT-001/"
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
  "keywords": "security, medium, terraform, MITRE T1552.004, CWE-321, D3-CR",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-AZURE-KV-CERT-001 — Azure Key Vault certificate missing auto-renewal policy

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-KV-CERT-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-KV-CERT-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-KV-CERT-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure Key Vault certificate missing auto-renewal policy.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_key_vault_certificate` (`certificate_policy`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_key_vault_certificate` has no `certificate_policy` block.
The certificate cannot be auto-renewed by Key Vault — an operator
must manually upload a new version before expiry, risking outage.

## Why it likely fired

`azurerm_key_vault_certificate` has no `certificate_policy` block.
The certificate cannot be auto-renewed by Key Vault — an operator
must manually upload a new version before expiry, risking outage.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-KV-CERT-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Embed a renewal policy that issues a new version some days before
expiry:

    resource "azurerm_key_vault_certificate" "main" {
      # ...
      certificate_policy {
        issuer_parameters { name = "Self" }
        key_properties {
          exportable = false
          key_type   = "RSA"
          key_size   = 2048
          reuse_key  = false
        }
        lifetime_action {
          action { action_type = "AutoRenew" }
          trigger { days_before_expiry = 30 }
        }
        secret_properties { content_type = "application/x-pkcs12" }
      }
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "azurerm_key_vault_certificate" "example" {
  name         = "example"
  key_vault_id = azurerm_key_vault.example.id
  certificate_policy {
    issuer_parameters { name = "Self" }
    key_properties {
      exportable = false
      key_type   = "RSA"
      key_size   = 2048
      reuse_key  = false
    }
    lifetime_action {
      action {
        action_type = "AutoRenew"
      }
      trigger {
        days_before_expiry = 30
      }
    }
    secret_properties { content_type = "application/x-pkcs12" }
  }
}
```

## Verification

```sh
`az keyvault certificate get-default-policy --vault-name <v> --name <c> \
  --query 'lifetimeActions[].action.actionType'` must include `AutoRenew`.
```

## References

**PCI-DSS**
  - `Req-4.1`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**MITRE ATT&CK**
  - [`T1552.004`](https://attack.mitre.org/techniques/T1552/004/)

**CWE**
  - [`CWE-321`](https://cwe.mitre.org/data/definitions/321.html)

**MITRE D3FEND**
  - [`D3-CR`](https://d3fend.mitre.org/technique/D3-CR/)

**NIST CSF 2.0**
  - [`PR.DS-2`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-12`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-12)

**Source**
  - [`catalog/SEC-AZURE-KV-CERT-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-KV-CERT-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-KV-CERT-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-KV-CERT-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-KV-CERT-001
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
