---
title: "STK-K8S-INGRESS-001 — kubernetes_ingress_v1 has no `tls` block (HTTP traffic exposed in clear)"
description: "tf-analyze rule STK-K8S-INGRESS-001 (HIGH · stack): kubernetes_ingress_v1 has no `tls` block (HTTP traffic exposed in clear)"
keywords: "stack, high, terraform, iac, cis-5.3.2, mitre-T1040, mitre-T1557, cwe-319, cwe-523, nist-csf-pr.ds-2, nist-800-53-sc-8, nist-800-53-sc-13, csa-ccm-ekm-04, csa-ccm-ivs-09"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-K8S-INGRESS-001 \u2014 kubernetes_ingress_v1 has no `tls` block (HTTP traffic exposed in clear)",
  "description": "Add a `tls` block referencing a Secret that holds the cert+key (or\nuse cert-manager + an `ExternalSecret` pulling from Vault). For\ningress-nginx + cert-manager, the canonical shape is an Ingress\nwith `tls.secretName` plus a `cert-manager.io",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-K8S-INGRESS-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-K8S-INGRESS-001/"
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
  "keywords": "stack, high, terraform, CIS 5.3.2, MITRE T1040, MITRE T1557, CWE-319, CWE-523",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-K8S-INGRESS-001 — kubernetes_ingress_v1 has no `tls` block (HTTP traffic exposed in clear)

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-K8S-INGRESS-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-K8S-INGRESS-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-K8S-INGRESS-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **kubernetes_ingress_v1 has no `tls` block (HTTP traffic exposed in clear).** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `kubernetes_ingress_v1` (`tls`) — _the resource is missing a required attribute (or nested attribute path)._
  `kubernetes_ingress_v1` has no `tls` block. Every host this
Ingress routes is reachable over plaintext HTTP — auth tokens
in headers, form bodies, and URL parameters are exposed to
anyone on the network path. The 2018 British Airways breach
(Magecart) pivoted on the assumption that internal traffic was
"safe" without TLS; the 2017 Equifax customer-portal breach
exposed traffic that the ops team believed was TLS-terminated
upstream but wasn't.
2. **`resource_missing_arg`** on `kubernetes_ingress` (`tls`) — _the resource is missing a required attribute (or nested attribute path)._
  `kubernetes_ingress` is the legacy v1beta1 alias. Same anti-pattern,
same fix.

## Why it likely fired

`kubernetes_ingress_v1` has no `tls` block. Every host this
Ingress routes is reachable over plaintext HTTP — auth tokens
in headers, form bodies, and URL parameters are exposed to
anyone on the network path. The 2018 British Airways breach
(Magecart) pivoted on the assumption that internal traffic was
"safe" without TLS; the 2017 Equifax customer-portal breach
exposed traffic that the ops team believed was TLS-terminated
upstream but wasn't.

`kubernetes_ingress` is the legacy v1beta1 alias. Same anti-pattern,
same fix.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-K8S-INGRESS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a `tls` block referencing a Secret that holds the cert+key (or
use cert-manager + an `ExternalSecret` pulling from Vault). For
ingress-nginx + cert-manager, the canonical shape is an Ingress
with `tls.secretName` plus a `cert-manager.io/cluster-issuer`
annotation that triggers cert issuance.

    resource "kubernetes_ingress_v1" "app" {
      metadata {
        name      = "app"
        namespace = "app"
        annotations = {
          "cert-manager.io/cluster-issuer" = "letsencrypt-prod"
        }
      }
      spec {
        tls {
          hosts       = ["app.example.com"]
          secret_name = "app-tls"
        }
        rule {
          host = "app.example.com"
          http {
            path {
              path      = "/"
              path_type = "Prefix"
              backend {
                service {
                  name = "app"
                  port { number = 80 }
                }
              }
            }
          }
        }
      }
    }

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "kubernetes_ingress_v1" "example" {
  metadata {
    name      = "example"
    namespace = "app"
    annotations = {
      "cert-manager.io/cluster-issuer" = "letsencrypt-prod"
    }
  }
  spec {
    tls {
      hosts       = ["app.example.com"]
      secret_name = "app-tls"
    }
    rule {
      host = "app.example.com"
      http {
        path {
          path      = "/"
          path_type = "Prefix"
          backend {
            service {
              name = "app"
              port { number = 80 }
            }
          }
        }
      }
    }
  }
}
```

_Adding TLS requires a cert Secret in place before apply (or cert-manager issuing one). HTTP→HTTPS redirect should be enabled at the ingress-controller level to avoid breaking existing HTTP clients._

## Verification

```sh
`kubectl get ingress -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\t"}{.spec.tls}{"\n"}{end}'`
must show a non-empty `tls` for every Ingress that routes public hosts.
```

## References

**CIS Benchmark**
  - `CIS 5.3.2`

**PCI-DSS**
  - `Req-4.2.1`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**MITRE ATT&CK**
  - [`T1040`](https://attack.mitre.org/techniques/T1040/)
  - [`T1557`](https://attack.mitre.org/techniques/T1557/)

**CWE**
  - [`CWE-319`](https://cwe.mitre.org/data/definitions/319.html)
  - [`CWE-523`](https://cwe.mitre.org/data/definitions/523.html)

**NIST CSF 2.0**
  - [`PR.DS-2`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-8`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-8)
  - [`SC-13`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-13)

**CSA CCM v4**
  - [`EKM-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)
  - [`IVS-09`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**OWASP (namespaced)**
  - `K06`

**Source**
  - [`catalog/STK-K8S-INGRESS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-K8S-INGRESS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-K8S-INGRESS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-K8S-INGRESS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-K8S-INGRESS-001
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
