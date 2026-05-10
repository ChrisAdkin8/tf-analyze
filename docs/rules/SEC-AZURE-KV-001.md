---
title: "SEC-AZURE-KV-001 — Azure Key Vault missing purge protection or soft delete"
description: "tf-analyze rule SEC-AZURE-KV-001 (HIGH · security): Azure Key Vault missing purge protection or soft delete"
keywords: "security, high, terraform, iac, azure, cis-8.4, mitre-T1530, cwe-311, d3-ear"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-KV-001 \u2014 Azure Key Vault missing purge protection or soft delete",
  "description": "Set `purge_protection_enabled = true` and `soft_delete_retention_days = 90`.\nWithout purge protection, an attacker (or accident) that deletes the Key Vault\nbypasses the soft-delete window by purging \u2014 secrets, keys, and certificates\nare gon",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-KV-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-KV-001/"
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
  "keywords": "security, high, terraform, CIS 8.4, MITRE T1530, CWE-311, D3-EAR",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AZURE-KV-001 — Azure Key Vault missing purge protection or soft delete

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-KV-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-KV-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-KV-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure Key Vault missing purge protection or soft delete.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`resource_arg`** on `azurerm_key_vault` (`purge_protection_enabled`) matching `/^false$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
2. **`resource_missing_arg`** on `azurerm_key_vault` (`purge_protection_enabled`) — _the resource is missing a required attribute (or nested attribute path)._
3. **`resource_arg`** on `azurerm_key_vault` (`soft_delete_retention_days`) matching `/^[0-6]$/` — _the resource declares the named attribute, but its value matches the rule's pattern._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-KV-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `purge_protection_enabled = true` and `soft_delete_retention_days = 90`.
Without purge protection, an attacker (or accident) that deletes the Key Vault
bypasses the soft-delete window by purging — secrets, keys, and certificates
are gone permanently.

    resource "azurerm_key_vault" "example" {
      # ...
      purge_protection_enabled    = true
      soft_delete_retention_days  = 90
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_key_vault" "example" {
  # ... other arguments ...
  purge_protection_enabled    = true
  soft_delete_retention_days  = 90
}
```

## Verification

After applying, confirm with:

    az keyvault show --name <name> \
      --query '{purgeProtection:properties.enablePurgeProtection,softDelete:properties.enableSoftDelete}'

Both values should return `true`.

## References

**CIS Benchmark**
  - `CIS 8.4`

**MITRE ATT&CK**
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)

**CWE**
  - [`CWE-311`](https://cwe.mitre.org/data/definitions/311.html)

**MITRE D3FEND**
  - [`D3-EAR`](https://d3fend.mitre.org/technique/D3-EAR/)

**Source**
  - [`catalog/SEC-AZURE-KV-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-KV-001.yaml) — canonical YAML

## Family

See also rules in the `SEC-AZURE-KV-*` family:

- [`SEC-AZURE-KV-002`](./SEC-AZURE-KV-002.md) — Key Vault missing network ACL deny-by-default
- [`SEC-AZURE-KV-003`](./SEC-AZURE-KV-003.md) — Azure Key Vault key missing rotation policy

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-KV-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-KV-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-KV-001
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
