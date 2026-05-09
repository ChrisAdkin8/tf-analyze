---
title: "SEC-K8S-HELM-001 — helm_release sets `service.type=LoadBalancer` (publicly exposed)"
description: "tf-analyze rule SEC-K8S-HELM-001 (HIGH · security): helm_release sets `service.type=LoadBalancer` (publicly exposed)"
keywords: "security, high, terraform, iac, cis-5.3.2, mitre-T1190, mitre-T1133"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-K8S-HELM-001 \u2014 helm_release sets `service.type=LoadBalancer` (publicly exposed)",
  "description": "Prefer `service.type = ClusterIP` plus an Ingress resource gated by\nan Ingress controller you control. The Ingress controller terminates\nTLS, enforces auth, and goes through a hardened LB once for the\nwhole cluster.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-HELM-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-HELM-001/"
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
  "keywords": "security, high, terraform, CIS 5.3.2, MITRE T1190, MITRE T1133",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-K8S-HELM-001 — helm_release sets `service.type=LoadBalancer` (publicly exposed)

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-K8S-HELM-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-K8S-HELM-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-K8S-HELM-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **helm_release sets `service.type=LoadBalancer` (publicly exposed).** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`helm_set_value`** matching `/^LoadBalancer$/` — _a `helm_release` `set { name = ...; value = ... }` override matches the listed condition._
  A `helm_release` block overrides `service.type` to `LoadBalancer`,
which provisions a cloud-level LB (ELB on AWS, GCLB on GCP,
Standard LB on Azure) directly attached to the chart's pods. The
pods are reachable from the public internet on whatever port the
chart exposes — no Ingress controller, WAF, or auth layer is
forced in front.

## Why it likely fired

A `helm_release` block overrides `service.type` to `LoadBalancer`,
which provisions a cloud-level LB (ELB on AWS, GCLB on GCP,
Standard LB on Azure) directly attached to the chart's pods. The
pods are reachable from the public internet on whatever port the
chart exposes — no Ingress controller, WAF, or auth layer is
forced in front.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-K8S-HELM-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Prefer `service.type = ClusterIP` plus an Ingress resource gated by
an Ingress controller you control. The Ingress controller terminates
TLS, enforces auth, and goes through a hardened LB once for the
whole cluster.

    resource "helm_release" "app" {
      # ...
      set {
        name  = "service.type"
        value = "ClusterIP"
      }
      set {
        name  = "ingress.enabled"
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
    name  = "service.type"
    value = "ClusterIP"
  }
}
```

_Switching service type drops the existing LB and reprovisions; in-flight connections drop._

## Verification

```sh
`kubectl get svc -A -o jsonpath='{.items[?(@.spec.type=="LoadBalancer")].metadata.name}'`
should not list workload services.
```

## References

**CIS Benchmark**
  - `CIS 5.3.2`

**PCI-DSS**
  - `Req-1.2`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**MITRE ATT&CK**
  - [`T1190`](https://attack.mitre.org/techniques/T1190/)
  - [`T1133`](https://attack.mitre.org/techniques/T1133/)

**Source**
  - [`catalog/SEC-K8S-HELM-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-K8S-HELM-001.yaml) — canonical YAML

## Family

See also rules in the `SEC-K8S-HELM-*` family:

- [`SEC-K8S-HELM-002`](./SEC-K8S-HELM-002.md) — helm_release sets `securityContext.privileged=true`

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-K8S-HELM-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-K8S-HELM-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-K8S-HELM-001
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
