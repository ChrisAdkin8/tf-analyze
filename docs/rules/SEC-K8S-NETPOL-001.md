---
title: "SEC-K8S-NETPOL-001 — kubernetes_network_policy absent for the corpus"
description: "tf-analyze rule SEC-K8S-NETPOL-001 (HIGH · security): kubernetes_network_policy absent for the corpus"
keywords: "security, high, terraform, iac, cis-5.3.2, mitre-T1611, nist-csf-pr.ac-5, nist-800-53-sc-7, csa-ccm-ivs-04"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-K8S-NETPOL-001 \u2014 kubernetes_network_policy absent for the corpus",
  "description": "Ship at minimum a default-deny egress + ingress policy in every\nworkload namespace, then layer specific allow rules on top:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-NETPOL-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-K8S-NETPOL-001/"
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
  "keywords": "security, high, terraform, CIS 5.3.2, MITRE T1611",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-K8S-NETPOL-001 — kubernetes_network_policy absent for the corpus

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-K8S-NETPOL-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-K8S-NETPOL-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-K8S-NETPOL-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **kubernetes_network_policy absent for the corpus.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_absent`** on `kubernetes_network_policy` — _the corpus is missing a resource type we expected to find given other resources present._
  The corpus declares `kubernetes_namespace` resources but no
`kubernetes_network_policy`. Without a NetworkPolicy every pod
can reach every other pod on every port — there is no
default-deny. An attacker who compromises one container scans
and pivots laterally without traversing any network barrier
(the 2018 Tesla cryptomining incident exploited exactly this).

## Why it likely fired

The corpus declares `kubernetes_namespace` resources but no
`kubernetes_network_policy`. Without a NetworkPolicy every pod
can reach every other pod on every port — there is no
default-deny. An attacker who compromises one container scans
and pivots laterally without traversing any network barrier
(the 2018 Tesla cryptomining incident exploited exactly this).

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-K8S-NETPOL-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Ship at minimum a default-deny egress + ingress policy in every
workload namespace, then layer specific allow rules on top:

    resource "kubernetes_network_policy" "default_deny" {
      metadata {
        name      = "default-deny"
        namespace = kubernetes_namespace.app.metadata[0].name
      }
      spec {
        pod_selector {}
        policy_types = ["Ingress", "Egress"]
      }
    }

Then add `allow-dns`, `allow-from-ingress-controller`, etc. as
separate policies that opt in.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "kubernetes_network_policy" "default_deny" {
  metadata {
    name      = "default-deny"
    namespace = kubernetes_namespace.app.metadata[0].name
  }
  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}
```

_Default-deny will break running traffic until allow rules are added. Roll out per-namespace in audit before enforce._

## Verification

```sh
`kubectl get networkpolicy -A` must return at least one policy per
workload namespace; `kubectl describe ns <name> | grep network`
should not be empty.
```

## References

**CIS Benchmark**
  - `CIS 5.3.2`

**PCI-DSS**
  - `Req-1.2`

**SOC 2 Trust Services Criteria**
  - `CC6.7`

**MITRE ATT&CK**
  - [`T1611`](https://attack.mitre.org/techniques/T1611/)

**NIST CSF 2.0**
  - [`PR.AC-5`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-7`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-7)

**CSA CCM v4**
  - [`IVS-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-K8S-NETPOL-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-K8S-NETPOL-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-K8S-NETPOL-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-K8S-NETPOL-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-K8S-NETPOL-001
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
