---
title: "SEC-K8S-RBAC-001 — ClusterRoleBinding grants cluster-admin"
description: "tf-analyze rule SEC-K8S-RBAC-001 (CRITICAL · security): ClusterRoleBinding grants cluster-admin"
keywords: "security, critical, terraform, iac, cis-5.1.1, mitre-T1078.004, mitre-T1098.001"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-K8S-RBAC-001 \u2014 ClusterRoleBinding grants cluster-admin",
  "description": "Replace the cluster-admin reference with a scoped ClusterRole or a\nnamespaced RoleBinding. If absolute-power access is genuinely\nrequired (rare; usually only for cluster operators), keep the\nbinding short-lived and attach it to a specific U",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-RBAC-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-RBAC-001/"
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
  "keywords": "security, critical, terraform, CIS 5.1.1, MITRE T1078.004, MITRE T1098.001",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 🚨 SEC-K8S-RBAC-001 — ClusterRoleBinding grants cluster-admin

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-K8S-RBAC-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-K8S-RBAC-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-K8S-RBAC-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **ClusterRoleBinding grants cluster-admin.** This rule has `default_urgency: CRITICAL` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`resource_body_contains`** on `kubernetes_cluster_role_binding` matching `/name\s*=\s*"cluster-admin"/` — _the resource body matches a regex inside the block._
  `kubernetes_cluster_role_binding` references the built-in
`cluster-admin` ClusterRole. Any subject bound to this binding
(ServiceAccount, User, Group) has full unrestricted access to
every API across every namespace — equivalent to root on every
node. Compromise of any pod or token bound through this binding
yields full cluster takeover.

## Why it likely fired

`kubernetes_cluster_role_binding` references the built-in
`cluster-admin` ClusterRole. Any subject bound to this binding
(ServiceAccount, User, Group) has full unrestricted access to
every API across every namespace — equivalent to root on every
node. Compromise of any pod or token bound through this binding
yields full cluster takeover.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-K8S-RBAC-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace the cluster-admin reference with a scoped ClusterRole or a
namespaced RoleBinding. If absolute-power access is genuinely
required (rare; usually only for cluster operators), keep the
binding short-lived and attach it to a specific User identity, not
a long-lived ServiceAccount.

    resource "kubernetes_role_binding" "app" {
      metadata {
        name      = "app"
        namespace = "app"
      }
      role_ref {
        api_group = "rbac.authorization.k8s.io"
        kind      = "ClusterRole"
        name      = "view"   # scoped, read-only
      }
      subject {
        kind      = "ServiceAccount"
        name      = "app"
        namespace = "app"
      }
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "kubernetes_role_binding" "scoped" {
  metadata {
    name      = "app-scoped"
    namespace = "app"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "view"
  }
  subject {
    kind      = "ServiceAccount"
    name      = "app"
    namespace = "app"
  }
}
```

_Replacing the binding is destructive — pods using the previous role will lose access until rebound. Stage the new binding alongside, migrate workloads, then delete the old one._

## Verification

```sh
`kubectl get clusterrolebindings -o jsonpath='{.items[?(@.roleRef.name=="cluster-admin")].subjects[*].name}'`
should not include any ServiceAccount in a workload namespace.
```

## References

**CIS Benchmark**
  - `CIS 5.1.1`

**PCI-DSS**
  - `Req-7.2.2`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**MITRE ATT&CK**
  - [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/)
  - [`T1098.001`](https://attack.mitre.org/techniques/T1098/001/)

**Source**
  - [`catalog/SEC-K8S-RBAC-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-K8S-RBAC-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-K8S-RBAC-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-K8S-RBAC-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-K8S-RBAC-001
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
