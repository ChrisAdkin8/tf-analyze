---
title: "SEC-K8S-RBAC-002 — RoleBinding / ClusterRoleBinding subject targets a broad system Group"
description: "tf-analyze rule SEC-K8S-RBAC-002 (CRITICAL · security): RoleBinding / ClusterRoleBinding subject targets a broad system Group"
keywords: "security, critical, terraform, iac, cis-5.1.1, cis-5.1.5, mitre-T1078.001, mitre-T1078.004, cwe-269, cwe-732, nist-csf-pr.ac-4, nist-800-53-ac-3, nist-800-53-ac-6, csa-ccm-iam-09"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-K8S-RBAC-002 \u2014 RoleBinding / ClusterRoleBinding subject targets a broad system Group",
  "description": "Drop the system-Group subject. If a workload needs the bound role,\nbind it to a scoped ServiceAccount in the workload's namespace\nrather than to a broad system Group. Reserve `system:masters` for\nthe kubeadm-bootstrap kubeconfig only.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-RBAC-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-RBAC-002/"
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
  "keywords": "security, critical, terraform, CIS 5.1.1, CIS 5.1.5, MITRE T1078.001, MITRE T1078.004, CWE-269, CWE-732",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 🚨 SEC-K8S-RBAC-002 — RoleBinding / ClusterRoleBinding subject targets a broad system Group

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-K8S-RBAC-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-K8S-RBAC-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-K8S-RBAC-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **RoleBinding / ClusterRoleBinding subject targets a broad system Group.** This rule has `default_urgency: CRITICAL` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`resource_body_contains`** on `kubernetes_role_binding` matching `/(?ms)subject\s*\{[^}]*kind\s*=\s*"Group"[^}]*name\s*=\s*"system:masters"/` — _the resource body matches a regex inside the block._
  `kubernetes_role_binding` has a subject `kind = "Group"` with
`name = "system:masters"`. `system:masters` is a hard-coded
group in kube-apiserver that bypasses RBAC entirely — every
member is treated as cluster-admin regardless of which role
this binding references. Used legitimately only by the bootstrap
kubeconfig.
2. **`resource_body_contains`** on `kubernetes_cluster_role_binding` matching `/(?ms)subject\s*\{[^}]*kind\s*=\s*"Group"[^}]*name\s*=\s*"system:masters"/` — _the resource body matches a regex inside the block._
  Same as above, but at cluster scope. `kubernetes_cluster_role_binding`
with `system:masters` as a subject grants the referenced role
to every kubeconfig that asserts the `system:masters` group —
typically the original bootstrap credential plus any cluster
operator who copy-pasted that kubeconfig.
3. **`resource_body_contains`** on `kubernetes_role_binding` matching `/(?ms)subject\s*\{[^}]*kind\s*=\s*"Group"[^}]*name\s*=\s*"system:unauthenticated"/` — _the resource body matches a regex inside the block._
  Subject `Group: system:unauthenticated` grants the role to every
request without a valid token. Effectively makes the role
reachable by any pod that can reach the API server, including
pods without service-account tokens mounted.
4. **`resource_body_contains`** on `kubernetes_cluster_role_binding` matching `/(?ms)subject\s*\{[^}]*kind\s*=\s*"Group"[^}]*name\s*=\s*"system:unauthenticated"/` — _the resource body matches a regex inside the block._
  Same as above at cluster scope. The 2018 Tesla Kubernetes
breach pivoted on an `system:unauthenticated`-readable dashboard
ClusterRoleBinding; the same anti-pattern is still common in
legacy installs of cluster-monitoring stacks.

## Why it likely fired

`kubernetes_role_binding` has a subject `kind = "Group"` with
`name = "system:masters"`. `system:masters` is a hard-coded
group in kube-apiserver that bypasses RBAC entirely — every
member is treated as cluster-admin regardless of which role
this binding references. Used legitimately only by the bootstrap
kubeconfig.

Same as above, but at cluster scope. `kubernetes_cluster_role_binding`
with `system:masters` as a subject grants the referenced role
to every kubeconfig that asserts the `system:masters` group —
typically the original bootstrap credential plus any cluster
operator who copy-pasted that kubeconfig.

Subject `Group: system:unauthenticated` grants the role to every
request without a valid token. Effectively makes the role
reachable by any pod that can reach the API server, including
pods without service-account tokens mounted.

Same as above at cluster scope. The 2018 Tesla Kubernetes
breach pivoted on an `system:unauthenticated`-readable dashboard
ClusterRoleBinding; the same anti-pattern is still common in
legacy installs of cluster-monitoring stacks.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-K8S-RBAC-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Drop the system-Group subject. If a workload needs the bound role,
bind it to a scoped ServiceAccount in the workload's namespace
rather than to a broad system Group. Reserve `system:masters` for
the kubeadm-bootstrap kubeconfig only.

    resource "kubernetes_role_binding" "app" {
      metadata {
        name      = "app"
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

_Removing the system-Group subject drops access for every principal in that group. Stage a replacement ServiceAccount binding first, then rotate kubeconfigs off the broad group._

## Verification

```sh
`kubectl get clusterrolebindings -o json | jq '.items[] | select(.subjects[]?.name | IN("system:masters","system:unauthenticated"))'`
should not list any binding outside `kube-system`.
```

## References

**CIS Benchmark**
  - `CIS 5.1.1`
  - `CIS 5.1.5`

**PCI-DSS**
  - `Req-7.2.2`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**MITRE ATT&CK**
  - [`T1078.001`](https://attack.mitre.org/techniques/T1078/001/)
  - [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/)

**CWE**
  - [`CWE-269`](https://cwe.mitre.org/data/definitions/269.html)
  - [`CWE-732`](https://cwe.mitre.org/data/definitions/732.html)

**NIST CSF 2.0**
  - [`PR.AC-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AC-3`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-3)
  - [`AC-6`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-6)

**CSA CCM v4**
  - [`IAM-09`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**OWASP (namespaced)**
  - `K03`

**Source**
  - [`catalog/SEC-K8S-RBAC-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-K8S-RBAC-002.yaml) — canonical YAML

## Family

See also rules in the `SEC-K8S-RBAC-*` family:

- [`SEC-K8S-RBAC-001`](./SEC-K8S-RBAC-001.md) — ClusterRoleBinding grants cluster-admin OR uses wildcard verbs / system:authenticated

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-K8S-RBAC-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-K8S-RBAC-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-K8S-RBAC-002
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
