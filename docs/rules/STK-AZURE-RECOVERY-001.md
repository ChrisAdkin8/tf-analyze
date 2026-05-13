---
title: "STK-AZURE-RECOVERY-001 — Azure Recovery Services Vault missing soft-delete protection"
description: "tf-analyze rule STK-AZURE-RECOVERY-001 (HIGH · stack): Azure Recovery Services Vault missing soft-delete protection"
keywords: "stack, high, terraform, iac, azure, cis-8.5, mitre-T1485, mitre-T1490, cwe-779, d3-dencr, nist-csf-pr.ip-4, nist-800-53-cp-9, csa-ccm-bcr-08"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AZURE-RECOVERY-001 \u2014 Azure Recovery Services Vault missing soft-delete protection",
  "description": "Enable soft-delete and (for high-RPO workloads) enable\nimmutability_settings:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-RECOVERY-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-RECOVERY-001/"
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
  "keywords": "stack, high, terraform, CIS 8.5, MITRE T1485, MITRE T1490, CWE-779, D3-DENCR",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-AZURE-RECOVERY-001 — Azure Recovery Services Vault missing soft-delete protection

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AZURE-RECOVERY-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-AZURE-RECOVERY-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-AZURE-RECOVERY-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure Recovery Services Vault missing soft-delete protection.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`resource_arg`** on `azurerm_recovery_services_vault` (`soft_delete_enabled`) matching `/^false$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `azurerm_recovery_services_vault.soft_delete_enabled = false`.
An attacker with backup-contributor rights can delete recovery
points immediately — no 14-day grace window for accidental or
malicious deletes. Equivalent to AWS Backup vault lock gap
(SEC-AWS-BACKUP-001).

## Why it likely fired

`azurerm_recovery_services_vault.soft_delete_enabled = false`.
An attacker with backup-contributor rights can delete recovery
points immediately — no 14-day grace window for accidental or
malicious deletes. Equivalent to AWS Backup vault lock gap
(SEC-AWS-BACKUP-001).

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-RECOVERY-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable soft-delete and (for high-RPO workloads) enable
immutability_settings:

    resource "azurerm_recovery_services_vault" "main" {
      # ...
      soft_delete_enabled = true
      immutability        = "Unlocked"
    }

Lock immutability to "Locked" once you're confident — after that
retention can only be extended, never shortened.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_recovery_services_vault" "example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Standard"
  soft_delete_enabled = true
  immutability        = "Unlocked"
}
```

## Verification

```sh
`az backup vault show -g <rg> -n <name> --query 'properties.securitySettings.softDeleteSettings.softDeleteState'`
must return `Enabled`.
```

## References

**CIS Benchmark**
  - `CIS 8.5`

**PCI-DSS**
  - `Req-3.1`

**SOC 2 Trust Services Criteria**
  - `A1.2`

**MITRE ATT&CK**
  - [`T1485`](https://attack.mitre.org/techniques/T1485/)
  - [`T1490`](https://attack.mitre.org/techniques/T1490/)

**CWE**
  - [`CWE-779`](https://cwe.mitre.org/data/definitions/779.html)

**MITRE D3FEND**
  - [`D3-DENCR`](https://d3fend.mitre.org/technique/D3-DENCR/)

**NIST CSF 2.0**
  - [`PR.IP-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`CP-9`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=cp-9)

**CSA CCM v4**
  - [`BCR-08`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/STK-AZURE-RECOVERY-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-RECOVERY-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-RECOVERY-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-RECOVERY-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-RECOVERY-001
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
