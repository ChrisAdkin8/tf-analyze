---
title: "STK-AZURE-AKS-VERSION-001 — Azure AKS cluster on end-of-life Kubernetes version"
description: "tf-analyze rule STK-AZURE-AKS-VERSION-001 (HIGH · stack): Azure AKS cluster on end-of-life Kubernetes version"
keywords: "stack, high, terraform, iac, azure, mitre-T1195.002, cwe-1104, d3-sca, nist-csf-id.sc-2, nist-800-53-sr-4, slsa-deps"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AZURE-AKS-VERSION-001 \u2014 Azure AKS cluster on end-of-life Kubernetes version",
  "description": "Upgrade to a supported AKS Kubernetes version (1.27+ as of May 2026).\nCheck the support matrix at\nhttps://learn.microsoft.com/azure/aks/supported-kubernetes-versions\nand test the upgrade in a non-production cluster first.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-AKS-VERSION-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-AKS-VERSION-001/"
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
  "keywords": "stack, high, terraform, MITRE T1195.002, CWE-1104, D3-SCA",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-AZURE-AKS-VERSION-001 — Azure AKS cluster on end-of-life Kubernetes version

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AZURE-AKS-VERSION-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-AZURE-AKS-VERSION-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-AZURE-AKS-VERSION-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure AKS cluster on end-of-life Kubernetes version.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`resource_arg`** on `azurerm_kubernetes_cluster` (`kubernetes_version`) matching `/^1\.(1[0-9]|2[0-6])(\..*)?$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `azurerm_kubernetes_cluster.kubernetes_version` is on a Kubernetes
release no longer supported by AKS (1.19–1.26 inclusive). EOL
versions stop receiving security patches; AKS may force-upgrade
them on a maintenance window the operator cannot defer.

## Why it likely fired

`azurerm_kubernetes_cluster.kubernetes_version` is on a Kubernetes
release no longer supported by AKS (1.19–1.26 inclusive). EOL
versions stop receiving security patches; AKS may force-upgrade
them on a maintenance window the operator cannot defer.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-AKS-VERSION-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Upgrade to a supported AKS Kubernetes version (1.27+ as of May 2026).
Check the support matrix at
https://learn.microsoft.com/azure/aks/supported-kubernetes-versions
and test the upgrade in a non-production cluster first.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "example"
  kubernetes_version  = "1.29.4"
  default_node_pool { name = "default" node_count = 1 vm_size = "Standard_D2s_v3" }
  identity { type = "SystemAssigned" }
}
```

## Verification

```sh
`az aks show -g <rg> -n <name> --query 'kubernetesVersion'` must
return a version Azure currently supports.
```

## References

**MITRE ATT&CK**
  - [`T1195.002`](https://attack.mitre.org/techniques/T1195/002/)

**CWE**
  - [`CWE-1104`](https://cwe.mitre.org/data/definitions/1104.html)

**MITRE D3FEND**
  - [`D3-SCA`](https://d3fend.mitre.org/technique/D3-SCA/)

**NIST CSF 2.0**
  - [`ID.SC-2`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SR-4`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sr-4)

**SLSA v1.0**
  - [`SLSA deps`](https://slsa.dev/spec/v1.0/deps-track)

**Source**
  - [`catalog/STK-AZURE-AKS-VERSION-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-AKS-VERSION-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-AKS-VERSION-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-AKS-VERSION-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-AKS-VERSION-001
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
