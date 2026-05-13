---
title: "SEC-AZURE-SQL-VULN-001 — Azure SQL Server missing vulnerability assessment"
description: "tf-analyze rule SEC-AZURE-SQL-VULN-001 (HIGH · security): Azure SQL Server missing vulnerability assessment"
keywords: "security, high, terraform, iac, azure, mitre-T1190, cwe-693, d3-sca, nist-csf-id.ra-1, nist-800-53-ra-5, csa-ccm-tvm-02"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-SQL-VULN-001 \u2014 Azure SQL Server missing vulnerability assessment",
  "description": "Bind a vulnerability assessment to the server:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-SQL-VULN-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-SQL-VULN-001/"
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
  "keywords": "security, high, terraform, MITRE T1190, CWE-693, D3-SCA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AZURE-SQL-VULN-001 — Azure SQL Server missing vulnerability assessment

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-SQL-VULN-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-SQL-VULN-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-SQL-VULN-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure SQL Server missing vulnerability assessment.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_absent`** on `azurerm_mssql_server_vulnerability_assessment` — _the corpus is missing a resource type we expected to find given other resources present._
  `azurerm_mssql_server` is declared but no
`azurerm_mssql_server_vulnerability_assessment` resource is
bound. Misconfigurations and known-bad SQL patterns
(excessive permissions, weak passwords, deprecated features) are
never surfaced.

## Why it likely fired

`azurerm_mssql_server` is declared but no
`azurerm_mssql_server_vulnerability_assessment` resource is
bound. Misconfigurations and known-bad SQL patterns
(excessive permissions, weak passwords, deprecated features) are
never surfaced.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-SQL-VULN-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Bind a vulnerability assessment to the server:

    resource "azurerm_mssql_server_vulnerability_assessment" "main" {
      server_security_alert_policy_id = azurerm_mssql_server_security_alert_policy.main.id
      storage_container_path          = "${azurerm_storage_account.va.primary_blob_endpoint}vulnerability-assessment/"
      storage_account_access_key      = azurerm_storage_account.va.primary_access_key
      recurring_scans {
        enabled                   = true
        email_subscription_admins = true
      }
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_mssql_server_vulnerability_assessment" "example" {
  server_security_alert_policy_id = azurerm_mssql_server_security_alert_policy.example.id
  storage_container_path          = "${azurerm_storage_account.va.primary_blob_endpoint}vulnerability-assessment/"
  storage_account_access_key      = azurerm_storage_account.va.primary_access_key
  recurring_scans {
    enabled = true
  }
}
```

## Verification

```sh
`az sql server vulnerability-assessment show -g <rg> --server <name>` must
return a non-null `storageContainerPath`.
```

## References

**PCI-DSS**
  - `Req-11.3`

**SOC 2 Trust Services Criteria**
  - `CC7.1`

**MITRE ATT&CK**
  - [`T1190`](https://attack.mitre.org/techniques/T1190/)

**CWE**
  - [`CWE-693`](https://cwe.mitre.org/data/definitions/693.html)

**MITRE D3FEND**
  - [`D3-SCA`](https://d3fend.mitre.org/technique/D3-SCA/)

**NIST CSF 2.0**
  - [`ID.RA-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`RA-5`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ra-5)

**CSA CCM v4**
  - [`TVM-02`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AZURE-SQL-VULN-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-SQL-VULN-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-SQL-VULN-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-SQL-VULN-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-SQL-VULN-001
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
