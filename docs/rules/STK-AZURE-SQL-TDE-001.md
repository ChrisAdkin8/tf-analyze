---
title: "STK-AZURE-SQL-TDE-001 — Azure SQL Database missing transparent data encryption resource"
description: "tf-analyze rule STK-AZURE-SQL-TDE-001 (HIGH · stack): Azure SQL Database missing transparent data encryption resource"
keywords: "stack, high, terraform, iac, azure, cis-4.1.1, mitre-T1530, cwe-311, d3-ear, nist-csf-pr.ds-1, nist-800-53-sc-13, nist-800-53-sc-28, csa-ccm-cek-03"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AZURE-SQL-TDE-001 \u2014 Azure SQL Database missing transparent data encryption resource",
  "description": "Add a TDE resource for every SQL database and pin it to `\"Enabled\"`:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-SQL-TDE-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-SQL-TDE-001/"
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
  "keywords": "stack, high, terraform, CIS 4.1.1, MITRE T1530, CWE-311, D3-EAR",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-AZURE-SQL-TDE-001 — Azure SQL Database missing transparent data encryption resource

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AZURE-SQL-TDE-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-AZURE-SQL-TDE-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-AZURE-SQL-TDE-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure SQL Database missing transparent data encryption resource.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. _Conditional: only applies when `azurerm ≥ 3.0`._

## What this checks

1. **`resource_absent`** on `azurerm_mssql_database_transparent_data_encryption` — _the corpus is missing a resource type we expected to find given other resources present._
  `azurerm_mssql_database` present but no
`azurerm_mssql_database_transparent_data_encryption` resource in
the repository. TDE encrypts data files, log files, and backups at
rest. Without an explicit TDE resource, encryption state depends on
provider defaults and cannot be audited or enforced in code.

## Why it likely fired

`azurerm_mssql_database` present but no
`azurerm_mssql_database_transparent_data_encryption` resource in
the repository. TDE encrypts data files, log files, and backups at
rest. Without an explicit TDE resource, encryption state depends on
provider defaults and cannot be audited or enforced in code.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-SQL-TDE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a TDE resource for every SQL database and pin it to `"Enabled"`:

    resource "azurerm_mssql_database_transparent_data_encryption" "app" {
      database_id = azurerm_mssql_database.app.id
      state       = "Enabled"
    }

For databases on SQL Managed Instance (not SQL Server), TDE is enabled
by default and managed at the instance level — this rule applies only
to `azurerm_mssql_database` on `azurerm_mssql_server`.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_mssql_database_transparent_data_encryption" "example" {
  database_id = azurerm_mssql_database.example.id
  state       = "Enabled"
}
```

## Verification

```sh
`az sql db tde show --database <db> --server <server> \
  --resource-group <rg> --query 'status'`
must return `"Enabled"`.
```

## References

**CIS Benchmark**
  - `CIS 4.1.1`

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
  - [`catalog/STK-AZURE-SQL-TDE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-SQL-TDE-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-SQL-TDE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-SQL-TDE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-SQL-TDE-001
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
