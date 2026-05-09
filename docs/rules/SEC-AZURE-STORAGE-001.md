---
title: "SEC-AZURE-STORAGE-001 — Azure storage account allows non-HTTPS traffic"
description: "tf-analyze rule SEC-AZURE-STORAGE-001 (HIGH · security): Azure storage account allows non-HTTPS traffic"
keywords: "security, high, terraform, iac, azure, cis-3.1"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-STORAGE-001 \u2014 Azure storage account allows non-HTTPS traffic",
  "description": "Set `https_only = true` (provider v3+) or `enable_https_traffic_only = true`\n(provider v2). Also set `min_tls_version = \"TLS1_2\"`. Allowing HTTP exposes\nstorage account keys and SAS tokens in transit.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-STORAGE-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-STORAGE-001/"
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
  "keywords": "security, high, terraform, CIS 3.1",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AZURE-STORAGE-001 — Azure storage account allows non-HTTPS traffic

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-STORAGE-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure storage account allows non-HTTPS traffic.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `azurerm_storage_account` (`enable_https_traffic_only`) matching `/^false$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
2. **`resource_arg`** on `azurerm_storage_account` (`https_only`) matching `/^false$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
3. **`resource_arg`** on `azurerm_storage_account` (`min_tls_version`) matching `/^(TLS1_0|TLS1_1)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-STORAGE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `https_only = true` (provider v3+) or `enable_https_traffic_only = true`
(provider v2). Also set `min_tls_version = "TLS1_2"`. Allowing HTTP exposes
storage account keys and SAS tokens in transit.

    resource "azurerm_storage_account" "example" {
      # ...
      https_only       = true
      min_tls_version  = "TLS1_2"
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_storage_account" "example" {
  # ... other arguments ...
  https_traffic_only_enabled = true
  min_tls_version            = "TLS1_2"
}
```

## Verification

After applying, confirm with:

    az storage account show --name <name> --query 'enableHttpsTrafficOnly'

The command should return `true`.

## References

**CIS Benchmark**
  - `CIS 3.1`

**Source**
  - [`catalog/SEC-AZURE-STORAGE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-STORAGE-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-STORAGE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-STORAGE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-STORAGE-001
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
