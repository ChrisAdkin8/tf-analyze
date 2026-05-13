---
title: "SEC-AZURE-AKS-PRIVATE-001 — Azure AKS cluster API server publicly accessible (not a private cluster)"
description: "tf-analyze rule SEC-AZURE-AKS-PRIVATE-001 (HIGH · security): Azure AKS cluster API server publicly accessible (not a private cluster)"
keywords: "security, high, terraform, iac, azure, cis-5.4.2, mitre-T1190, cwe-284, d3-nta, nist-csf-pr.ac-5, nist-800-53-sc-7, csa-ccm-ivs-06"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-AKS-PRIVATE-001 \u2014 Azure AKS cluster API server publicly accessible (not a private cluster)",
  "description": "Enable private cluster mode and reach the API server through the\nprivate endpoint:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-AKS-PRIVATE-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-AKS-PRIVATE-001/"
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
  "keywords": "security, high, terraform, CIS 5.4.2, MITRE T1190, CWE-284, D3-NTA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AZURE-AKS-PRIVATE-001 — Azure AKS cluster API server publicly accessible (not a private cluster)

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-AKS-PRIVATE-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AZURE-AKS-PRIVATE-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AZURE-AKS-PRIVATE-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure AKS cluster API server publicly accessible (not a private cluster).** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_kubernetes_cluster` (`private_cluster_enabled`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_kubernetes_cluster` has no `private_cluster_enabled = true`.
The API server is reachable from the public internet (subject to
authorized_ip_ranges, but the attack surface is still public).
Equivalent to SEC-AWS-EKS-001 (EKS public endpoint).
2. **`resource_arg`** on `azurerm_kubernetes_cluster` (`private_cluster_enabled`) matching `/^false$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  AKS cluster explicitly sets private_cluster_enabled = false

## Why it likely fired

`azurerm_kubernetes_cluster` has no `private_cluster_enabled = true`.
The API server is reachable from the public internet (subject to
authorized_ip_ranges, but the attack surface is still public).
Equivalent to SEC-AWS-EKS-001 (EKS public endpoint).

AKS cluster explicitly sets private_cluster_enabled = false

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-AKS-PRIVATE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable private cluster mode and reach the API server through the
private endpoint:

    resource "azurerm_kubernetes_cluster" "main" {
      # ...
      private_cluster_enabled             = true
      private_dns_zone_id                 = "System"
      private_cluster_public_fqdn_enabled = false
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                    = "example"
  location                = azurerm_resource_group.example.location
  resource_group_name     = azurerm_resource_group.example.name
  dns_prefix              = "example"
  private_cluster_enabled = true
  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2s_v3"
  }
  identity { type = "SystemAssigned" }
}
```

## Verification

```sh
`az aks show -g <rg> -n <name> --query 'apiServerAccessProfile.enablePrivateCluster'`
must return `true`.
```

## References

**CIS Benchmark**
  - `CIS 5.4.2`

**PCI-DSS**
  - `Req-1.3`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**MITRE ATT&CK**
  - [`T1190`](https://attack.mitre.org/techniques/T1190/)

**CWE**
  - [`CWE-284`](https://cwe.mitre.org/data/definitions/284.html)

**MITRE D3FEND**
  - [`D3-NTA`](https://d3fend.mitre.org/technique/D3-NTA/)

**NIST CSF 2.0**
  - [`PR.AC-5`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-7`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-7)

**CSA CCM v4**
  - [`IVS-06`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AZURE-AKS-PRIVATE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-AKS-PRIVATE-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-AKS-PRIVATE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-AKS-PRIVATE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-AKS-PRIVATE-001
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
