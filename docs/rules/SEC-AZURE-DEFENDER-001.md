---
title: "SEC-AZURE-DEFENDER-001 — Microsoft Defender for Cloud not enabled on subscription"
description: "tf-analyze rule SEC-AZURE-DEFENDER-001 (HIGH · security): Microsoft Defender for Cloud not enabled on subscription"
keywords: "security, high, terraform, iac, azure, cis-2.1, mitre-T1078, cwe-693, d3-nta, nist-csf-de.cm-1, nist-csf-de.cm-7, nist-800-53-si-4, nist-800-53-ra-5, csa-ccm-tvm-04"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-DEFENDER-001 \u2014 Microsoft Defender for Cloud not enabled on subscription",
  "description": "Enable Defender for Cloud Standard tier on the resource_types that are\nin use (VMs, AppServices, SqlServers, StorageAccounts, KeyVaults,\nArm, Dns, Containers, etc.):",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-DEFENDER-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-DEFENDER-001/"
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
  "keywords": "security, high, terraform, CIS 2.1, MITRE T1078, CWE-693, D3-NTA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AZURE-DEFENDER-001 — Microsoft Defender for Cloud not enabled on subscription

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-DEFENDER-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-DEFENDER-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-DEFENDER-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Microsoft Defender for Cloud not enabled on subscription.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_arg`** on `azurerm_security_center_subscription_pricing` (`tier`) matching `/^Free$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `azurerm_security_center_subscription_pricing` has `tier = "Free"`,
which disables Microsoft Defender for Cloud's advanced threat
protection (vuln scanning, anomaly detection, threat intel).
2. **`resource_absent`** on `azurerm_security_center_subscription_pricing` — _the corpus is missing a resource type we expected to find given other resources present._
  No `azurerm_security_center_subscription_pricing` declared. Defender
for Cloud's enhanced security features (Standard tier) provide
runtime threat detection across VMs, App Service, SQL, Storage,
Containers, Key Vault, Resource Manager, DNS, and ARM. Without an
explicit Standard-tier subscription, the subscription falls back to
the Free tier (CSPM only, no threat detection).

## Why it likely fired

`azurerm_security_center_subscription_pricing` has `tier = "Free"`,
which disables Microsoft Defender for Cloud's advanced threat
protection (vuln scanning, anomaly detection, threat intel).

No `azurerm_security_center_subscription_pricing` declared. Defender
for Cloud's enhanced security features (Standard tier) provide
runtime threat detection across VMs, App Service, SQL, Storage,
Containers, Key Vault, Resource Manager, DNS, and ARM. Without an
explicit Standard-tier subscription, the subscription falls back to
the Free tier (CSPM only, no threat detection).

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-DEFENDER-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable Defender for Cloud Standard tier on the resource_types that are
in use (VMs, AppServices, SqlServers, StorageAccounts, KeyVaults,
Arm, Dns, Containers, etc.):

    resource "azurerm_security_center_subscription_pricing" "vm" {
      tier          = "Standard"
      resource_type = "VirtualMachines"
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_security_center_subscription_pricing" "vm" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "storage" {
  tier          = "Standard"
  resource_type = "StorageAccounts"
}
```

_Defender activation has no plane-of-control impact; it adds per-resource cost (see Azure pricing)._

## Verification

```sh
`az security pricing list --query "value[].{name:name,tier:pricingTier}"`
must show `Standard` for each in-use resource_type.
```

## References

**CIS Benchmark**
  - `CIS 2.1`

**PCI-DSS**
  - `Req-10.6`

**SOC 2 Trust Services Criteria**
  - `CC7.2`

**MITRE ATT&CK**
  - [`T1078`](https://attack.mitre.org/techniques/T1078/)

**CWE**
  - [`CWE-693`](https://cwe.mitre.org/data/definitions/693.html)

**MITRE D3FEND**
  - [`D3-NTA`](https://d3fend.mitre.org/technique/D3-NTA/)

**NIST CSF 2.0**
  - [`DE.CM-1`](https://www.nist.gov/cyberframework)
  - [`DE.CM-7`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SI-4`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=si-4)
  - [`RA-5`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ra-5)

**CSA CCM v4**
  - [`TVM-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AZURE-DEFENDER-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-DEFENDER-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-DEFENDER-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-DEFENDER-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-DEFENDER-001
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
