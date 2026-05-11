---
title: "SEC-AZURE-MONITOR-001 — Azure subscription missing activity log diagnostic setting"
description: "tf-analyze rule SEC-AZURE-MONITOR-001 (HIGH · security): Azure subscription missing activity log diagnostic setting"
keywords: "security, high, terraform, iac, azure, cis-5.2.1, mitre-T1562.008, cwe-778, d3-faa, nist-csf-de.cm-1, nist-800-53-au-2, csa-ccm-log-02"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-MONITOR-001 \u2014 Azure subscription missing activity log diagnostic setting",
  "description": "Add an `azurerm_subscription_diagnostic_setting` to forward subscription\nActivity Logs to a Log Analytics workspace or storage account:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-MONITOR-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-MONITOR-001/"
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
  "keywords": "security, high, terraform, CIS 5.2.1, MITRE T1562.008, CWE-778, D3-FAA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AZURE-MONITOR-001 — Azure subscription missing activity log diagnostic setting

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-MONITOR-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-MONITOR-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-MONITOR-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure subscription missing activity log diagnostic setting.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_absent`** on `azurerm_subscription_diagnostic_setting` — _the corpus is missing a resource type we expected to find given other resources present._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-MONITOR-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add an `azurerm_subscription_diagnostic_setting` to forward subscription
Activity Logs to a Log Analytics workspace or storage account:

    resource "azurerm_subscription_diagnostic_setting" "activity" {
      name               = "activity-log-to-law"
      target_resource_id = "/subscriptions/${var.subscription_id}"

      log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

      enabled_log {
        category = "Administrative"
      }
      enabled_log {
        category = "Security"
      }
      enabled_log {
        category = "Alert"
      }
      enabled_log {
        category = "Policy"
      }
    }

Without this, all Resource Manager API calls (create/delete/modify) age out
at the platform's 90-day retention with no long-term archive. Post-incident
investigations are blind beyond that window.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_subscription_diagnostic_setting" "activity" {
  name                       = "activity-to-law"
  target_resource_id         = "/subscriptions/${var.subscription_id}"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  enabled_log { category = "Administrative" }
  enabled_log { category = "Security" }
  enabled_log { category = "Alert" }
  enabled_log { category = "Policy" }
}
```

## Verification

```sh
`az monitor diagnostic-settings subscriptions list` must return at least one
setting with Log Analytics or storage sink. Re-run tf-analyze mode:verify-fixed.
```

## References

**CIS Benchmark**
  - `CIS 5.2.1`

**MITRE ATT&CK**
  - [`T1562.008`](https://attack.mitre.org/techniques/T1562/008/)

**CWE**
  - [`CWE-778`](https://cwe.mitre.org/data/definitions/778.html)

**MITRE D3FEND**
  - [`D3-FAA`](https://d3fend.mitre.org/technique/D3-FAA/)

**NIST CSF 2.0**
  - [`DE.CM-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AU-2`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=au-2)

**CSA CCM v4**
  - [`LOG-02`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AZURE-MONITOR-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-MONITOR-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-MONITOR-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-MONITOR-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-MONITOR-001
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
