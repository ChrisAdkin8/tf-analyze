---
title: "STK-AZURE-MYSQL-EOL-001 — Azure MySQL/PostgreSQL flexible server on end-of-life version"
description: "tf-analyze rule STK-AZURE-MYSQL-EOL-001 (HIGH · stack): Azure MySQL/PostgreSQL flexible server on end-of-life version"
keywords: "stack, high, terraform, iac, azure, mitre-T1195.002, cwe-1104, d3-sca, nist-csf-id.sc-2, nist-800-53-sr-4, slsa-deps"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AZURE-MYSQL-EOL-001 \u2014 Azure MySQL/PostgreSQL flexible server on end-of-life version",
  "description": "Upgrade to a supported version:\n- MySQL: 8.0 (LTS) or 8.4\n- PostgreSQL: 14, 15, 16",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-MYSQL-EOL-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-MYSQL-EOL-001/"
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
  "keywords": "stack, high, terraform, MITRE T1195.002, CWE-1104, D3-SCA",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-AZURE-MYSQL-EOL-001 — Azure MySQL/PostgreSQL flexible server on end-of-life version

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AZURE-MYSQL-EOL-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-AZURE-MYSQL-EOL-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-AZURE-MYSQL-EOL-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure MySQL/PostgreSQL flexible server on end-of-life version.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `azurerm_mysql_flexible_server` (`version`) matching `/^(5\.6|5\.7)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  MySQL flexible server on 5.6/5.7 (EOL upstream)
2. **`resource_arg`** on `azurerm_postgresql_flexible_server` (`version`) matching `/^(9\.6|10|11)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  PostgreSQL flexible server on 9.6/10/11 (EOL upstream)

## Why it likely fired

MySQL flexible server on 5.6/5.7 (EOL upstream)

PostgreSQL flexible server on 9.6/10/11 (EOL upstream)

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-MYSQL-EOL-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Upgrade to a supported version:
- MySQL: 8.0 (LTS) or 8.4
- PostgreSQL: 14, 15, 16

Test the upgrade in a non-production fork first; some breaking
changes affect query syntax (e.g. PostgreSQL 12 unified
`pg_resetxlog` → `pg_resetwal`).

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "azurerm_postgresql_flexible_server" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  version             = "16"
  sku_name            = "GP_Standard_D2s_v3"
  storage_mb          = 32768
  administrator_login    = "pgadmin"
  administrator_password = "REDACTED"
}
```

## Verification

```sh
`az mysql flexible-server show -g <rg> -n <name> --query 'version'`
must return a non-EOL major version.
```

## References

**MITRE ATT&CK**
  - [`T1195.002`](https://attack.mitre.org/techniques/T1195/002/)

**CWE**
  - [`CWE-1104`](https://cwe.mitre.org/data/definitions/1104.html)

**MITRE D3FEND**
  - [`D3-SCA`](https://d3fend.mitre.org/technique/D3-SCA/)

**NIST CSF 2.0**
  - [`ID.SC-2`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SR-4`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sr-4)

**SLSA v1.0**
  - [`SLSA deps`](https://slsa.dev/spec/v1.0/deps-track)

**Source**
  - [`catalog/STK-AZURE-MYSQL-EOL-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-MYSQL-EOL-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-MYSQL-EOL-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-MYSQL-EOL-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-MYSQL-EOL-001
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
