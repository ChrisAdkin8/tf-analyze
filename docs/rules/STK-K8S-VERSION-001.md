---
title: "STK-K8S-VERSION-001 — EKS/GKE/AKS cluster pinned to a Kubernetes version older than N-2"
description: "tf-analyze rule STK-K8S-VERSION-001 (HIGH · stack): EKS/GKE/AKS cluster pinned to a Kubernetes version older than N-2"
keywords: "stack, high, terraform, iac, mitre-T1190, mitre-T1068, cwe-1395, cwe-1104"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-K8S-VERSION-001 \u2014 EKS/GKE/AKS cluster pinned to a Kubernetes version older than N-2",
  "description": "Bump to a supported Kubernetes minor (N-2 floor). EKS/GKE/AKS each\npublish a support matrix \u2014 running below N-2 means no security\npatches and increasingly large CVE backlog. OWASP K05 (Inadequate\nLogging and Monitoring) compounds when the p",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-K8S-VERSION-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-K8S-VERSION-001/"
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
  "keywords": "stack, high, terraform, MITRE T1190, MITRE T1068, CWE-1395, CWE-1104",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-K8S-VERSION-001 — EKS/GKE/AKS cluster pinned to a Kubernetes version older than N-2

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-K8S-VERSION-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-K8S-VERSION-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-K8S-VERSION-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **EKS/GKE/AKS cluster pinned to a Kubernetes version older than N-2.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_arg`** on `aws_eks_cluster` (`version`) matching `/^(?:1\.(?:1[0-9]|2[0-7]))$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  EKS pinned to <= 1.27 (N-2 floor at time of writing)
2. **`resource_arg`** on `google_container_cluster` (`min_master_version`) matching `/^(?:1\.(?:1[0-9]|2[0-7]))/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  GKE pinned to <= 1.27
3. **`resource_arg`** on `azurerm_kubernetes_cluster` (`kubernetes_version`) matching `/^(?:1\.(?:1[0-9]|2[0-7]))/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  AKS pinned to <= 1.27

## Why it likely fired

EKS pinned to <= 1.27 (N-2 floor at time of writing)

GKE pinned to <= 1.27

AKS pinned to <= 1.27

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-K8S-VERSION-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Bump to a supported Kubernetes minor (N-2 floor). EKS/GKE/AKS each
publish a support matrix — running below N-2 means no security
patches and increasingly large CVE backlog. OWASP K05 (Inadequate
Logging and Monitoring) compounds when the platform itself is past
EOL because admission-controller + audit-log features arrive
per-minor.

Plan rolling upgrades; node pools must be drained and recreated.

## Verification

```sh
`aws eks describe-cluster --name <c> --query 'cluster.version'`
→ confirm >= current N-2.
```

## References

**MITRE ATT&CK**
  - [`T1190`](https://attack.mitre.org/techniques/T1190/)
  - [`T1068`](https://attack.mitre.org/techniques/T1068/)

**CWE**
  - [`CWE-1395`](https://cwe.mitre.org/data/definitions/1395.html)
  - [`CWE-1104`](https://cwe.mitre.org/data/definitions/1104.html)

**Source**
  - [`catalog/STK-K8S-VERSION-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-K8S-VERSION-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-K8S-VERSION-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-K8S-VERSION-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-K8S-VERSION-001
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
