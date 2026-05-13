---
title: "SEC-AZURE-STORAGE-004 — Azure storage account missing diagnostic logging"
description: "tf-analyze rule SEC-AZURE-STORAGE-004 (MEDIUM · security): Azure storage account missing diagnostic logging"
keywords: "security, medium, terraform, iac, azure, cis-3.11, mitre-T1530, mitre-T1213, cwe-778, d3-iaa, nist-csf-de.cm-1, nist-csf-pr.pt-1, nist-800-53-au-2, nist-800-53-au-12, csa-ccm-log-08"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-STORAGE-004 \u2014 Azure storage account missing diagnostic logging",
  "description": "Either configure `queue_properties.logging` on the account, or attach\nan `azurerm_monitor_diagnostic_setting` resource that ships\n`StorageRead` / `StorageWrite` / `StorageDelete` to a Log Analytics\nworkspace, Event Hub, or storage destinati",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-STORAGE-004/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-STORAGE-004/"
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
  "keywords": "security, medium, terraform, CIS 3.11, MITRE T1530, MITRE T1213, CWE-778, D3-IAA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-AZURE-STORAGE-004 — Azure storage account missing diagnostic logging

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-STORAGE-004" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-STORAGE-004" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-STORAGE-004 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure storage account missing diagnostic logging.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_storage_account` (`queue_properties`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_storage_account` has no `queue_properties.logging` block
and no companion `azurerm_monitor_diagnostic_setting` declared.
Without diagnostic logging, blob/queue/table read/write/delete
operations and authentication failures are not captured for
forensic analysis or compliance attestation.

## Why it likely fired

`azurerm_storage_account` has no `queue_properties.logging` block
and no companion `azurerm_monitor_diagnostic_setting` declared.
Without diagnostic logging, blob/queue/table read/write/delete
operations and authentication failures are not captured for
forensic analysis or compliance attestation.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-STORAGE-004` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Either configure `queue_properties.logging` on the account, or attach
an `azurerm_monitor_diagnostic_setting` resource that ships
`StorageRead` / `StorageWrite` / `StorageDelete` to a Log Analytics
workspace, Event Hub, or storage destination:

    resource "azurerm_monitor_diagnostic_setting" "sa" {
      name                       = "sa-diag"
      target_resource_id         = azurerm_storage_account.main.id
      log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
      enabled_log { category = "StorageRead" }
      enabled_log { category = "StorageWrite" }
      enabled_log { category = "StorageDelete" }
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_monitor_diagnostic_setting" "sa" {
  name                       = "${azurerm_storage_account.example.name}-diag"
  target_resource_id         = "${azurerm_storage_account.example.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id
  enabled_log { category = "StorageRead" }
  enabled_log { category = "StorageWrite" }
  enabled_log { category = "StorageDelete" }
}
```

## Verification

```sh
`az monitor diagnostic-settings list --resource <storage-account-id>` must
return at least one configuration with `StorageRead`, `StorageWrite`, and
`StorageDelete` log categories enabled.
```

## References

**CIS Benchmark**
  - `CIS 3.11`

**PCI-DSS**
  - `Req-10.2`

**SOC 2 Trust Services Criteria**
  - `CC7.2`

**MITRE ATT&CK**
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)
  - [`T1213`](https://attack.mitre.org/techniques/T1213/)

**CWE**
  - [`CWE-778`](https://cwe.mitre.org/data/definitions/778.html)

**MITRE D3FEND**
  - [`D3-IAA`](https://d3fend.mitre.org/technique/D3-IAA/)

**NIST CSF 2.0**
  - [`DE.CM-1`](https://www.nist.gov/cyberframework)
  - [`PR.PT-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AU-2`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=au-2)
  - [`AU-12`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=au-12)

**CSA CCM v4**
  - [`LOG-08`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AZURE-STORAGE-004.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-STORAGE-004.yaml) — canonical YAML

## Family

See also rules in the `SEC-AZURE-STORAGE-*` family:

- [`SEC-AZURE-STORAGE-001`](./SEC-AZURE-STORAGE-001.md) — Azure storage account allows non-HTTPS traffic
- [`SEC-AZURE-STORAGE-002`](./SEC-AZURE-STORAGE-002.md) — Azure storage account allows public blob access
- [`SEC-AZURE-STORAGE-003`](./SEC-AZURE-STORAGE-003.md) — Azure storage account not using customer-managed key encryption

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-STORAGE-004    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-STORAGE-004` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-STORAGE-004
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
