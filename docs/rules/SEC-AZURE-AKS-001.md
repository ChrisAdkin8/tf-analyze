---
title: "SEC-AZURE-AKS-001 — AKS cluster RBAC disabled"
description: "tf-analyze rule SEC-AZURE-AKS-001 (HIGH · security): AKS cluster RBAC disabled"
keywords: "security, high, terraform, iac, azure, cis-5.2, mitre-T1078.004, nist-csf-pr.ac-1, nist-800-53-ia-2, csa-ccm-iam-02"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-AKS-001 \u2014 AKS cluster RBAC disabled",
  "description": "Set `role_based_access_control_enabled = true` and configure\n`azure_active_directory_role_based_access_control`. Without RBAC, any\nauthenticated user can perform any action in the cluster.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-AKS-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-AKS-001/"
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
  "keywords": "security, high, terraform, CIS 5.2, MITRE T1078.004",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AZURE-AKS-001 — AKS cluster RBAC disabled

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-AKS-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-AKS-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-AKS-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **AKS cluster RBAC disabled.** This rule has `default_urgency: HIGH` and operates on a module blast radius. _Conditional: only applies when `azurerm ≥ 3.0`._

## What this checks

1. **`resource_arg`** on `azurerm_kubernetes_cluster` (`role_based_access_control_enabled`) matching `/^false$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
2. **`resource_missing_arg`** on `azurerm_kubernetes_cluster` (`azure_active_directory_role_based_access_control`) — _the resource is missing a required attribute (or nested attribute path)._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-AKS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `role_based_access_control_enabled = true` and configure
`azure_active_directory_role_based_access_control`. Without RBAC, any
authenticated user can perform any action in the cluster.

    resource "azurerm_kubernetes_cluster" "example" {
      # ...
      role_based_access_control_enabled = true

      azure_active_directory_role_based_access_control {
        managed                = true
        admin_group_object_ids = [var.aks_admin_group_id]
        azure_rbac_enabled     = true
      }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                              = "example"
  resource_group_name               = azurerm_resource_group.example.name
  location                          = azurerm_resource_group.example.location
  dns_prefix                        = "example"
  role_based_access_control_enabled = true
  azure_active_directory_role_based_access_control {
    managed            = true
    azure_rbac_enabled = true
  }
  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }
  identity { type = "SystemAssigned" }
}
```

## Verification

After applying, confirm with:

    az aks show --name <name> --resource-group <rg> --query 'enableRBAC'

The command should return `true`.

## References

**CIS Benchmark**
  - `CIS 5.2`

**MITRE ATT&CK**
  - [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/)

**NIST CSF 2.0**
  - [`PR.AC-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`IA-2`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ia-2)

**CSA CCM v4**
  - [`IAM-02`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AZURE-AKS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-AKS-001.yaml) — canonical YAML

## Family

See also rules in the `SEC-AZURE-AKS-*` family:

- [`SEC-AZURE-AKS-002`](./SEC-AZURE-AKS-002.md) — AKS cluster missing network policy

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-AKS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-AKS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-AKS-001
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
