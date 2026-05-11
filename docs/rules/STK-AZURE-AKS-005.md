---
title: "STK-AZURE-AKS-005 — AKS cluster API server missing authorized IP ranges"
description: "tf-analyze rule STK-AZURE-AKS-005 (MEDIUM · stack): AKS cluster API server missing authorized IP ranges"
keywords: "stack, medium, terraform, iac, azure, mitre-T1190, mitre-T1133, cwe-284, d3-iaa, nist-csf-pr.ac-3, nist-800-53-sc-7, csa-ccm-ivs-04"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AZURE-AKS-005 \u2014 AKS cluster API server missing authorized IP ranges",
  "description": "Restrict API server access to known CIDRs (CI runners, operator VPN\negress IPs, bastion host subnets):",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-AKS-005/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-AKS-005/"
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
  "keywords": "stack, medium, terraform, MITRE T1190, MITRE T1133, CWE-284, D3-IAA",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# 💡 STK-AZURE-AKS-005 — AKS cluster API server missing authorized IP ranges

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AZURE-AKS-005" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-AZURE-AKS-005" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-AZURE-AKS-005 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **AKS cluster API server missing authorized IP ranges.** This rule has `default_urgency: MEDIUM` and operates on a environment blast radius. _Conditional: only applies when `azurerm ≥ 3.0`._

## What this checks

1. **`resource_missing_arg`** on `azurerm_kubernetes_cluster` (`api_server_access_profile.authorized_ip_ranges`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_kubernetes_cluster` without
`api_server_access_profile { authorized_ip_ranges }`. The public
Kubernetes API endpoint accepts connections from any IP address.
Even with valid credentials required, brute-force and credential-
stuffing attacks can target the API from anywhere on the internet.

## Why it likely fired

`azurerm_kubernetes_cluster` without
`api_server_access_profile { authorized_ip_ranges }`. The public
Kubernetes API endpoint accepts connections from any IP address.
Even with valid credentials required, brute-force and credential-
stuffing attacks can target the API from anywhere on the internet.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-AKS-005` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Restrict API server access to known CIDRs (CI runners, operator VPN
egress IPs, bastion host subnets):

    resource "azurerm_kubernetes_cluster" "app" {
      api_server_access_profile {
        authorized_ip_ranges = [
          "203.0.113.0/24",  # CI runner egress
          "10.0.0.0/8",      # internal VNet
        ]
      }
    }

The recommended target is `private_cluster_enabled = true`
(STK-AZURE-AKS-004). Authorized IP ranges are a defence-in-depth
layer for clusters that must retain a public endpoint.
Equivalent to GKE `master_authorized_networks_config`.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  dns_prefix          = "example"
  api_server_access_profile {
    authorized_ip_ranges = ["203.0.113.0/24"]
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

```sh
`az aks show --name <cluster> --resource-group <rg> \
  --query 'apiServerAccessProfile.authorizedIpRanges'`
must return a non-empty list.
```

## References

**MITRE ATT&CK**
  - [`T1190`](https://attack.mitre.org/techniques/T1190/)
  - [`T1133`](https://attack.mitre.org/techniques/T1133/)

**CWE**
  - [`CWE-284`](https://cwe.mitre.org/data/definitions/284.html)

**MITRE D3FEND**
  - [`D3-IAA`](https://d3fend.mitre.org/technique/D3-IAA/)

**NIST CSF 2.0**
  - [`PR.AC-3`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-7`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-7)

**CSA CCM v4**
  - [`IVS-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/STK-AZURE-AKS-005.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-AKS-005.yaml) — canonical YAML

## Family

See also rules in the `STK-AZURE-AKS-*` family:

- [`STK-AZURE-AKS-003`](./STK-AZURE-AKS-003.md) — AKS cluster workload identity not enabled
- [`STK-AZURE-AKS-004`](./STK-AZURE-AKS-004.md) — AKS cluster API server is publicly accessible

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-AKS-005    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-AKS-005` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-AKS-005
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
