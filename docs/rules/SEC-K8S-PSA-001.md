---
title: "SEC-K8S-PSA-001 — kubernetes_namespace missing PSA label OR helm_release omits runAsNonRoot / readOnlyRootFilesystem / capabilities.drop"
description: "tf-analyze rule SEC-K8S-PSA-001 (HIGH · security): kubernetes_namespace missing PSA label OR helm_release omits runAsNonRoot / readOnlyRootFilesystem / cap…"
keywords: "security, high, terraform, iac, cis-5.2.1, cis-5.7.3, mitre-T1611, cwe-269, cwe-250"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-K8S-PSA-001 \u2014 kubernetes_namespace missing PSA label OR helm_release omits runAsNonRoot / readOnlyRootFilesystem / capabilities.drop",
  "description": "Add the PSA enforcement label to every namespace, scoped to the\nleast-privileged level the workload tolerates:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-PSA-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-PSA-001/"
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
  "keywords": "security, high, terraform, CIS 5.2.1, CIS 5.7.3, MITRE T1611, CWE-269, CWE-250",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-K8S-PSA-001 — kubernetes_namespace missing PSA label OR helm_release omits runAsNonRoot / readOnlyRootFilesystem / capabilities.drop

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-K8S-PSA-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-K8S-PSA-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-K8S-PSA-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **kubernetes_namespace missing PSA label OR helm_release omits runAsNonRoot / readOnlyRootFilesystem / capabilities.drop.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `kubernetes_namespace` (`metadata.labels`) — _the resource is missing a required attribute (or nested attribute path)._
  `kubernetes_namespace` block has no `metadata.labels` (or labels
without `pod-security.kubernetes.io/enforce`). Without a Pod
Security Admission level, the namespace defaults to no enforcement
— privileged pods, hostPath mounts, and host-network pods are all
permitted. PSA replaced the deprecated PodSecurityPolicy in 1.25.
2. **`helm_set_value`** on `helm_release` — _a `helm_release` `set { name = ...; value = ... }` override matches the listed condition._
  R30.5 / NIST 800-190 — helm_release must set
`securityContext.runAsNonRoot = true`. Containers running as
uid 0 inside the pod expose the host to capability escalations.
3. **`helm_set_value`** on `helm_release` — _a `helm_release` `set { name = ...; value = ... }` override matches the listed condition._
  R30.5 / NIST 800-190 — helm_release must set
`securityContext.readOnlyRootFilesystem = true`. A writable
rootfs lets attackers persist tooling across pod restarts.
4. **`helm_set_value`** on `helm_release` — _a `helm_release` `set { name = ...; value = ... }` override matches the listed condition._
  R30.5 / NIST 800-190 — drop ALL kernel capabilities and add back
only what the app needs. Default Linux capabilities (CAP_NET_RAW
etc.) give a compromised pod meaningful escalation surface.

## Why it likely fired

`kubernetes_namespace` block has no `metadata.labels` (or labels
without `pod-security.kubernetes.io/enforce`). Without a Pod
Security Admission level, the namespace defaults to no enforcement
— privileged pods, hostPath mounts, and host-network pods are all
permitted. PSA replaced the deprecated PodSecurityPolicy in 1.25.

R30.5 / NIST 800-190 — helm_release must set
`securityContext.runAsNonRoot = true`. Containers running as
uid 0 inside the pod expose the host to capability escalations.

R30.5 / NIST 800-190 — helm_release must set
`securityContext.readOnlyRootFilesystem = true`. A writable
rootfs lets attackers persist tooling across pod restarts.

R30.5 / NIST 800-190 — drop ALL kernel capabilities and add back
only what the app needs. Default Linux capabilities (CAP_NET_RAW
etc.) give a compromised pod meaningful escalation surface.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-K8S-PSA-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add the PSA enforcement label to every namespace, scoped to the
least-privileged level the workload tolerates:

    resource "kubernetes_namespace" "app" {
      metadata {
        name = "app"
        labels = {
          "pod-security.kubernetes.io/enforce"         = "restricted"
          "pod-security.kubernetes.io/enforce-version" = "latest"
        }
      }
    }

Use `baseline` for legacy workloads that still need privileged
capabilities; `restricted` is the right default for new workloads.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "kubernetes_namespace" "example" {
  metadata {
    name = "example"
    labels = {
      "pod-security.kubernetes.io/enforce"         = "restricted"
      "pod-security.kubernetes.io/enforce-version" = "latest"
    }
  }
}
```

_Tightening PSA on a running namespace can reject pending pods that violate the level. Roll out in audit mode first._

## Verification

```sh
`kubectl get ns -o jsonpath='{.items[*].metadata.labels.pod-security\.kubernetes\.io/enforce}'`
must list a level for every non-system namespace.
```

## References

**CIS Benchmark**
  - `CIS 5.2.1`
  - `CIS 5.7.3`

**PCI-DSS**
  - `Req-2.2`

**SOC 2 Trust Services Criteria**
  - `CC6.6`

**MITRE ATT&CK**
  - [`T1611`](https://attack.mitre.org/techniques/T1611/)

**CWE**
  - [`CWE-269`](https://cwe.mitre.org/data/definitions/269.html)
  - [`CWE-250`](https://cwe.mitre.org/data/definitions/250.html)

**Source**
  - [`catalog/SEC-K8S-PSA-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-K8S-PSA-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-K8S-PSA-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-K8S-PSA-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-K8S-PSA-001
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
