---
title: "SEC-K8S-HELM-002 — helm_release sets `securityContext.privileged=true`"
description: "tf-analyze rule SEC-K8S-HELM-002 (CRITICAL · security): helm_release sets `securityContext.privileged=true`"
keywords: "security, critical, terraform, iac, cis-5.2.4, mitre-T1611, mitre-T1068"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-K8S-HELM-002 \u2014 helm_release sets `securityContext.privileged=true`",
  "description": "Drop `privileged=true`. Almost no production workload genuinely\nneeds it \u2014 required capabilities should be granted explicitly via\n`securityContext.capabilities.add`. If the chart truly requires it,\npin to a Pod Security Admission `privilege",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-HELM-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-HELM-002/"
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
  "keywords": "security, critical, terraform, CIS 5.2.4, MITRE T1611, MITRE T1068",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 🚨 SEC-K8S-HELM-002 — helm_release sets `securityContext.privileged=true`

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-K8S-HELM-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **helm_release sets `securityContext.privileged=true`.** This rule has `default_urgency: CRITICAL` and operates on a environment blast radius. 

## What this checks

1. **`helm_set_value`** matching `/(?i)^true$/` — _a `helm_release` `set { name = ...; value = ... }` override matches the listed condition._
  A `helm_release` override sets `securityContext.privileged=true`
on the chart's pod spec. Privileged containers run with full
host capabilities, including write access to the host filesystem
via `/proc` and `/sys`, and can mount arbitrary host devices.
A single RCE in such a container yields node-level compromise
(the standard cloud-native breakout pattern).

## Why it likely fired

A `helm_release` override sets `securityContext.privileged=true`
on the chart's pod spec. Privileged containers run with full
host capabilities, including write access to the host filesystem
via `/proc` and `/sys`, and can mount arbitrary host devices.
A single RCE in such a container yields node-level compromise
(the standard cloud-native breakout pattern).

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-K8S-HELM-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Drop `privileged=true`. Almost no production workload genuinely
needs it — required capabilities should be granted explicitly via
`securityContext.capabilities.add`. If the chart truly requires it,
pin to a Pod Security Admission `privileged` namespace and require
manual sign-off.

    resource "helm_release" "app" {
      set {
        name  = "securityContext.privileged"
        value = "false"
      }
      set {
        name  = "securityContext.runAsNonRoot"
        value = "true"
      }
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "helm_release" "example" {
  name       = "example"
  repository = "https://charts.example.io"
  chart      = "example"
  set {
    name  = "securityContext.privileged"
    value = "false"
  }
  set {
    name  = "securityContext.runAsNonRoot"
    value = "true"
  }
}
```

_Pods will be recreated with the new securityContext; charts that genuinely require host access will fail to start._

## Verification

```sh
`kubectl get pods -A -o jsonpath='{.items[?(@.spec.containers[*].securityContext.privileged==true)].metadata.name}'`
must return empty.
```

## References

**CIS Benchmark**
  - `CIS 5.2.4`

**PCI-DSS**
  - `Req-2.2`

**SOC 2 Trust Services Criteria**
  - `CC6.6`

**MITRE ATT&CK**
  - [`T1611`](https://attack.mitre.org/techniques/T1611/)
  - [`T1068`](https://attack.mitre.org/techniques/T1068/)

**Source**
  - [`catalog/SEC-K8S-HELM-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-K8S-HELM-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-K8S-HELM-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-K8S-HELM-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-K8S-HELM-002
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
