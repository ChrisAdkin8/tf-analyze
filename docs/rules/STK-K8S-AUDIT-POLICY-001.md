---
title: "STK-K8S-AUDIT-POLICY-001 — Managed Kubernetes control plane has no audit-log configuration"
description: "tf-analyze rule STK-K8S-AUDIT-POLICY-001 (MEDIUM · stack): Managed Kubernetes control plane has no audit-log configuration"
keywords: "stack, medium, terraform, iac, mitre-T1562.008, mitre-T1530, cwe-778, cwe-223"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-K8S-AUDIT-POLICY-001 \u2014 Managed Kubernetes control plane has no audit-log configuration",
  "description": "# EKS\nresource \"aws_eks_cluster\" \"app\" {\n  name = \"primary\"\n  enabled_cluster_log_types = [\n    \"api\", \"audit\", \"authenticator\",\n    \"controllerManager\", \"scheduler\",\n  ]\n  # \u2026\n}",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-K8S-AUDIT-POLICY-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-K8S-AUDIT-POLICY-001/"
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
  "keywords": "stack, medium, terraform, MITRE T1562.008, MITRE T1530, CWE-778, CWE-223",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# 💡 STK-K8S-AUDIT-POLICY-001 — Managed Kubernetes control plane has no audit-log configuration

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-K8S-AUDIT-POLICY-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-K8S-AUDIT-POLICY-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-K8S-AUDIT-POLICY-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Managed Kubernetes control plane has no audit-log configuration.** This rule has `default_urgency: MEDIUM` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_eks_cluster` (`enabled_cluster_log_types`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_eks_cluster` without `enabled_cluster_log_types` ships
with NO control-plane audit logging — api, audit, authenticator,
controllerManager, scheduler are all off by default. NSA
Kubernetes Hardening (Sec 5) + OWASP K05 require at least
`api` and `audit` for incident response.
2. **`resource_missing_arg`** on `google_container_cluster` (`logging_service`) — _the resource is missing a required attribute (or nested attribute path)._
  GKE cluster without `logging_service` configured
3. **`resource_missing_arg`** on `azurerm_kubernetes_cluster` (`oms_agent`) — _the resource is missing a required attribute (or nested attribute path)._
  AKS cluster without `oms_agent` block (Log Analytics)

## Why it likely fired

`aws_eks_cluster` without `enabled_cluster_log_types` ships
with NO control-plane audit logging — api, audit, authenticator,
controllerManager, scheduler are all off by default. NSA
Kubernetes Hardening (Sec 5) + OWASP K05 require at least
`api` and `audit` for incident response.

GKE cluster without `logging_service` configured

AKS cluster without `oms_agent` block (Log Analytics)

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-K8S-AUDIT-POLICY-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

# EKS
resource "aws_eks_cluster" "app" {
  name = "primary"
  enabled_cluster_log_types = [
    "api", "audit", "authenticator",
    "controllerManager", "scheduler",
  ]
  # …
}

# GKE
resource "google_container_cluster" "app" {
  logging_service    = "logging.googleapis.com/kubernetes"
  monitoring_service = "monitoring.googleapis.com/kubernetes"
  # …
}

# AKS
resource "azurerm_kubernetes_cluster" "app" {
  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.app.id
  }
  # …
}

## Verification

```sh
`aws eks describe-cluster --name <c> --query 'cluster.logging.clusterLogging'`
— each desired type should show `enabled: true`.
```

## References

**MITRE ATT&CK**
  - [`T1562.008`](https://attack.mitre.org/techniques/T1562/008/)
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)

**CWE**
  - [`CWE-778`](https://cwe.mitre.org/data/definitions/778.html)
  - [`CWE-223`](https://cwe.mitre.org/data/definitions/223.html)

**Source**
  - [`catalog/STK-K8S-AUDIT-POLICY-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-K8S-AUDIT-POLICY-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-K8S-AUDIT-POLICY-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-K8S-AUDIT-POLICY-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-K8S-AUDIT-POLICY-001
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
