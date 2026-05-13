---
title: "STK-K8S-PSA-002 — kubernetes_namespace Pod Security Admission `enforce` level is `privileged` (no enforcement)"
description: "tf-analyze rule STK-K8S-PSA-002 (HIGH · stack): kubernetes_namespace Pod Security Admission `enforce` level is `privileged` (no enforcement)"
keywords: "stack, high, terraform, iac, cis-5.2.1, mitre-T1611, cwe-250, cwe-269, nist-csf-pr.pt-3, nist-800-53-cm-7, csa-ccm-ais-07"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-K8S-PSA-002 \u2014 kubernetes_namespace Pod Security Admission `enforce` level is `privileged` (no enforcement)",
  "description": "Raise the enforce level to `baseline` (blocks the worst-known\nfoot-guns) or `restricted` (defense-in-depth, recommended for new\nworkloads). Use the `warn` and `audit` levels to identify pods\nthat would be rejected before flipping enforce.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-K8S-PSA-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-K8S-PSA-002/"
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
  "keywords": "stack, high, terraform, CIS 5.2.1, MITRE T1611, CWE-250, CWE-269",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-K8S-PSA-002 — kubernetes_namespace Pod Security Admission `enforce` level is `privileged` (no enforcement)

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-K8S-PSA-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-K8S-PSA-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-K8S-PSA-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **kubernetes_namespace Pod Security Admission `enforce` level is `privileged` (no enforcement).** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_body_contains`** on `kubernetes_namespace` matching `/"pod-security\.kubernetes\.io/enforce"\s*=\s*"privileged"/` — _the resource body matches a regex inside the block._
  `kubernetes_namespace` has `pod-security.kubernetes.io/enforce`
set to `privileged` — the weakest of the three PSA levels.
Every PodSecurityPolicy-equivalent violation is permitted in
this namespace: privileged containers, host-namespace sharing,
hostPath mounts, hostNetwork pods. Functionally equivalent to
having no PSA label at all.

## Why it likely fired

`kubernetes_namespace` has `pod-security.kubernetes.io/enforce`
set to `privileged` — the weakest of the three PSA levels.
Every PodSecurityPolicy-equivalent violation is permitted in
this namespace: privileged containers, host-namespace sharing,
hostPath mounts, hostNetwork pods. Functionally equivalent to
having no PSA label at all.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-K8S-PSA-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Raise the enforce level to `baseline` (blocks the worst-known
foot-guns) or `restricted` (defense-in-depth, recommended for new
workloads). Use the `warn` and `audit` levels to identify pods
that would be rejected before flipping enforce.

    resource "kubernetes_namespace" "app" {
      metadata {
        name = "app"
        labels = {
          "pod-security.kubernetes.io/enforce"         = "restricted"
          "pod-security.kubernetes.io/enforce-version" = "latest"
          "pod-security.kubernetes.io/warn"            = "restricted"
          "pod-security.kubernetes.io/audit"           = "restricted"
        }
      }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "kubernetes_namespace" "example" {
  metadata {
    name = "example"
    labels = {
      "pod-security.kubernetes.io/enforce"         = "restricted"
      "pod-security.kubernetes.io/enforce-version" = "latest"
      "pod-security.kubernetes.io/warn"            = "restricted"
      "pod-security.kubernetes.io/audit"           = "restricted"
    }
  }
}
```

_Tightening from `privileged` to `restricted` will reject pending pods that don't meet the restricted profile (runAsNonRoot, drop all caps). Roll out via the `warn` level first to identify which workloads need remediation._

## Verification

```sh
`kubectl get ns -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.labels.pod-security\.kubernetes\.io/enforce}{"\n"}{end}'`
should not list any workload namespace with `privileged`.
```

## References

**CIS Benchmark**
  - `CIS 5.2.1`

**PCI-DSS**
  - `Req-2.2`

**SOC 2 Trust Services Criteria**
  - `CC6.6`

**MITRE ATT&CK**
  - [`T1611`](https://attack.mitre.org/techniques/T1611/)

**CWE**
  - [`CWE-250`](https://cwe.mitre.org/data/definitions/250.html)
  - [`CWE-269`](https://cwe.mitre.org/data/definitions/269.html)

**NIST CSF 2.0**
  - [`PR.PT-3`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`CM-7`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=cm-7)

**CSA CCM v4**
  - [`AIS-07`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**OWASP (namespaced)**
  - `K01`
  - `K04`

**Source**
  - [`catalog/STK-K8S-PSA-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-K8S-PSA-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-K8S-PSA-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-K8S-PSA-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-K8S-PSA-002
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
