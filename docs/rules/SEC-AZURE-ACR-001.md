---
title: "SEC-AZURE-ACR-001 — Azure Container Registry admin account enabled"
description: "tf-analyze rule SEC-AZURE-ACR-001 (HIGH · security): Azure Container Registry admin account enabled"
keywords: "security, high, terraform, iac, azure, mitre-T1078.004, cwe-250, nist-csf-pr.ac-4, nist-800-53-ac-6, csa-ccm-iam-09"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-ACR-001 \u2014 Azure Container Registry admin account enabled",
  "description": "Disable the admin account and use Entra ID authentication:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-ACR-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-ACR-001/"
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
  "keywords": "security, high, terraform, MITRE T1078.004, CWE-250",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AZURE-ACR-001 — Azure Container Registry admin account enabled

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-ACR-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-ACR-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-ACR-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure Container Registry admin account enabled.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`hcl_attr`** on `azurerm_container_registry` (`admin_enabled`) not equal to `False` — _an attribute value differs from the expected literal._
  `azurerm_container_registry` with `admin_enabled = true`. The admin
account uses a shared username and password with full read/write
access to all repositories in the registry. It cannot be scoped,
audited per-user, or rotated without re-pushing credentials to all
consumers. Equivalent to keeping the root account active in an IAM
system. Use Entra ID service principals or managed identities with
AcrPull / AcrPush role assignments instead.

## Why it likely fired

`azurerm_container_registry` with `admin_enabled = true`. The admin
account uses a shared username and password with full read/write
access to all repositories in the registry. It cannot be scoped,
audited per-user, or rotated without re-pushing credentials to all
consumers. Equivalent to keeping the root account active in an IAM
system. Use Entra ID service principals or managed identities with
AcrPull / AcrPush role assignments instead.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-ACR-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Disable the admin account and use Entra ID authentication:

    resource "azurerm_container_registry" "app" {
      name                = "acrapp"
      resource_group_name = azurerm_resource_group.app.name
      location            = azurerm_resource_group.app.location
      sku                 = "Standard"
      admin_enabled       = false
    }

    resource "azurerm_role_assignment" "aks_pull" {
      scope                = azurerm_container_registry.app.id
      role_definition_name = "AcrPull"
      principal_id         = azurerm_kubernetes_cluster.app.kubelet_identity[0].object_id
    }

ACR supports task identities, managed identities for Azure services,
and service principal tokens — none of which need the admin account.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_container_registry" "example" {
  name                = "exampleacr"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Standard"
  admin_enabled       = false
}
```

## Verification

```sh
`az acr show --name <registry> --resource-group <rg> \
  --query 'adminUserEnabled'`
must return `false`.
```

## References

**MITRE ATT&CK**
  - [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/)

**CWE**
  - [`CWE-250`](https://cwe.mitre.org/data/definitions/250.html)

**NIST CSF 2.0**
  - [`PR.AC-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AC-6`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-6)

**CSA CCM v4**
  - [`IAM-09`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AZURE-ACR-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-ACR-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-ACR-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-ACR-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-ACR-001
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
